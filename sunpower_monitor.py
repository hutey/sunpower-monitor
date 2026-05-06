#!/usr/bin/env python3
"""
SunPower / SunStrong Local Monitor  (varserver API, firmware 2025.09+)
─────────────────────────────────────────────────────────────────────
Reads live data from your PVS6 on the local network using the new
authenticated varserver FCGI API, and serves a dashboard at
http://localhost:5001.

Usage:
  pip3 install flask requests urllib3
  PVS_HOST=192.168.1.x PVS_PASSWORD=XXXXX python3 sunpower_monitor.py

Notes:
  - PVS_HOST should be the IP of your PVS6 (no http/https prefix — the
    script uses HTTPS with the self-signed cert automatically).
  - PVS_PASSWORD is the LAST 5 CHARACTERS of your PVS6 serial number.
  - Requires PVS6 firmware build 61840 or newer.

Based on SunStrong's official LocalAPI spec:
  https://github.com/SunStrong-Management/pypvs/blob/main/doc/LocalAPI.md
"""

import os
import json
import base64
import threading
from pathlib import Path
import requests
import urllib3
import ipaddress
import time
from datetime import datetime, date
from flask import Flask, jsonify, render_template, request

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
def _load_config():
    """Load config.json from the same directory as this script, if present."""
    cfg_path = Path(__file__).parent / "config.json"
    if cfg_path.exists():
        try:
            with open(cfg_path) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

_cfg = _load_config()
PVS_HOST      = os.environ.get("PVS_HOST",        _cfg.get("pvs_host",     "sunpowerlocal")).strip()
PVS_PASSWORD  = os.environ.get("PVS_PASSWORD",    _cfg.get("pvs_password", "")).strip()
PORT          = int(os.environ.get("FLASK_RUN_PORT", _cfg.get("port",      5001)))
CT_CORRECTION = os.environ.get("CT_CORRECTION", str(_cfg.get("ct_correction", True))).lower() not in ("false", "0", "no")

for prefix in ("https://", "http://"):
    if PVS_HOST.startswith(prefix):
        PVS_HOST = PVS_HOST[len(prefix):]
PVS_HOST = PVS_HOST.rstrip("/")

BASE_URL = f"https://{PVS_HOST}"

# ── Tailscale access detection ─────────────────────────────────────────────────
# Direct Tailscale VPN connections arrive from 100.64.0.0/10 (CGNAT range).
# Tailscale Funnel connections are proxied locally and always carry X-Forwarded-For.
TAILSCALE_RANGE = ipaddress.ip_network("100.64.0.0/10")

def is_tailscale_direct():
    """True for direct Tailscale VPN or local access; False for Tailscale Funnel."""
    if "X-Forwarded-For" in request.headers:
        return False          # Funnel proxy always injects this header
    try:
        ip = ipaddress.ip_address(request.remote_addr or "")
        return ip in TAILSCALE_RANGE or ip.is_loopback
    except ValueError:
        return False

def _redact_str(s, keep=4):
    """Redact all but the last `keep` characters of a string."""
    if not s or s in ("—", ""):
        return s
    s = str(s)
    return "••••" + s[-keep:] if len(s) > keep else "••••"

def redact_for_public(data):
    """Strip sensitive identifiers for public (Funnel) viewers."""
    import copy
    data = copy.deepcopy(data)
    # Supervisor — redact MAC
    sup = data.get("supervisor", {})
    sup["mac"] = _redact_str(sup.get("mac"))
    # Panels — redact full serial (serial_short kept for display)
    for p in data.get("panels", []):
        p["serial"] = _redact_str(p.get("serial"))
    # Diagnostics — redact meter serials
    diag = data.get("diagnostics", {})
    for key in ("production_meter", "consumption_meter"):
        m = diag.get(key)
        if isinstance(m, dict):
            m["serial"] = _redact_str(m.get("serial"))
    data["pvs_host"] = "••••"
    data["access"] = "public"
    return data

# ── Rate limiting ─────────────────────────────────────────────────────────────
_rl_lock  = threading.Lock()
_rl_store = {}          # ip -> [timestamp, ...]
RL_LIMIT  = 60          # max requests per window per IP
RL_WINDOW = 60          # window in seconds

@app.before_request
def rate_limit():
    if not request.path.startswith("/api/"):
        return
    ip = (request.headers.get("X-Forwarded-For") or request.remote_addr or "").split(",")[0].strip()
    now = time.time()
    with _rl_lock:
        hits = [t for t in _rl_store.get(ip, []) if now - t < RL_WINDOW]
        if len(hits) >= RL_LIMIT:
            return jsonify({"ok": False, "error": "rate_limited",
                            "message": "Too many requests — please slow down."}), 429
        hits.append(now)
        _rl_store[ip] = hits

# ── Auth session ──────────────────────────────────────────────────────────────
_session = requests.Session()
_session.verify = False
_authenticated = False


def login():
    global _authenticated
    if not PVS_PASSWORD:
        raise ValueError(
            "PVS_PASSWORD not set. Use the LAST 5 CHARACTERS of your PVS serial.\n"
            "Example: PVS_PASSWORD=XXXXX python3 sunpower_monitor.py"
        )
    auth_b64 = base64.b64encode(f"ssm_owner:{PVS_PASSWORD}".encode()).decode()
    headers  = {"Authorization": f"basic {auth_b64}"}
    resp = _session.get(f"{BASE_URL}/auth?login", headers=headers, timeout=15)
    if resp.status_code == 401:
        raise PermissionError(
            "Login rejected (401). Check PVS_PASSWORD — must be the last 5 "
            "characters of the serial, case-sensitive."
        )
    resp.raise_for_status()
    body = resp.json()
    if "session" not in body:
        raise PermissionError(f"Unexpected login response: {body}")
    _session.headers.update(headers)
    _authenticated = True
    return True


def varserver_get(query_string):
    global _authenticated
    if not _authenticated:
        login()
    url = f"{BASE_URL}/vars?{query_string}"
    resp = _session.get(url, timeout=15)
    if resp.status_code in (401, 403):
        _authenticated = False
        login()
        resp = _session.get(url, timeout=15)
    resp.raise_for_status()
    return resp.json()


# ── Persistent daily history ──────────────────────────────────────────────────
# Structure:
#   {
#     "baselines": { "YYYY-MM-DD": { serial: first_lifetime_kwh_seen_that_day } },
#     "last_seen": { "YYYY-MM-DD": { serial: most_recent_lifetime_kwh_that_day } }
#   }
# Daily production per panel = last_seen[D] - baselines[D]. Survives restarts.
HISTORY_FILE = Path(__file__).parent / "history.json"
_history_lock = threading.Lock()
_history_cache = None


def _load_history():
    global _history_cache
    if _history_cache is not None:
        return _history_cache
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE) as f:
                _history_cache = json.load(f)
        except Exception:
            _history_cache = {}
    else:
        _history_cache = {}
    _history_cache.setdefault("baselines", {})
    _history_cache.setdefault("last_seen", {})
    return _history_cache


def _save_history():
    if _history_cache is None:
        return
    tmp = HISTORY_FILE.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(_history_cache, f, indent=2, sort_keys=True)
    tmp.replace(HISTORY_FILE)


def record_reading(serial, current_kwh):
    """Record today's baseline/last-seen for this serial and return today's kWh."""
    today = date.today().isoformat()
    with _history_lock:
        data = _load_history()
        day_base = data["baselines"].setdefault(today, {})
        day_last = data["last_seen"].setdefault(today, {})
        changed = False
        if serial not in day_base:
            day_base[serial] = current_kwh
            changed = True
        if day_last.get(serial) != current_kwh:
            day_last[serial] = current_kwh
            changed = True
        if changed:
            _save_history()
        baseline = day_base[serial]
    return round(max(0.0, current_kwh - baseline), 3)


# ── Data fetching & parsing ───────────────────────────────────────────────────
def _group_by_device(flat):
    """Group flat varserver output like {'/sys/devices/inverter/0/sn': '...'}
    into {'0': {'sn': '...', ...}, '1': {...}}."""
    grouped = {}
    for key, value in flat.items():
        parts = key.strip("/").split("/")
        if len(parts) < 5:
            continue
        idx, field = parts[-2], parts[-1]
        grouped.setdefault(idx, {})[field] = value
    return grouped


def fetch_all_data():
    inverters = _group_by_device(varserver_get("match=inverter&fmt=obj"))
    try:
        meters = _group_by_device(varserver_get("match=meter&fmt=obj"))
    except Exception:
        meters = {}
    try:
        livedata = varserver_get("match=/sys/livedata&fmt=obj")
    except Exception:
        livedata = {}
    try:
        sysinfo = varserver_get("match=/sys/info&fmt=obj")
    except Exception:
        sysinfo = {}

    # ── Inverters (per-panel) ─────────────────────────────────────────────────
    panels = []
    for key, inv in inverters.items():
        if not isinstance(inv, dict):
            continue
        serial   = inv.get("sn", key)
        kw       = float(inv.get("pMppt1Kw", 0) or 0)
        kwh_life = float(inv.get("ltea3phsumKwh", 0) or 0)
        panels.append({
            "serial":       serial,
            "serial_short": serial[-6:] if len(serial) >= 6 else serial,
            "model":        inv.get("prodMdlNm", "—"),
            "state":        "working" if kw > 0 else "idle",
            "kw":           round(kw, 4),
            "watts":        round(kw * 1000, 1),
            "kwh_life":     round(kwh_life, 2),
            "kwh_today":    record_reading(serial, kwh_life),
            "voltage":      round(float(inv.get("vln3phavgV", 0) or 0), 1),
            "dc_voltage":   round(float(inv.get("vMppt1V", 0) or 0), 1),
            "current_a":    round(float(inv.get("iMppt1A", 0) or 0), 2),
            "temp_c":       inv.get("tHtsnkDegc"),
            "freq_hz":      round(float(inv.get("freqHz", 0) or 0), 2),
            "last_seen":    inv.get("msmtEps", "—"),
        })
    panels.sort(key=lambda p: p["serial_short"])

    # ── Aggregate ─────────────────────────────────────────────────────────────
    total_kw        = round(sum(p["kw"]        for p in panels), 3)
    total_kwh_today = round(sum(p["kwh_today"] for p in panels), 2)
    total_kwh_life  = round(sum(p["kwh_life"]  for p in panels), 2)
    online          = sum(1 for p in panels if p["watts"] > 0)

    def _f(v):
        try: return float(v)
        except: return None

    ld_pv_p   = _f(livedata.get("/sys/livedata/pv_p"))
    ld_pv_en  = _f(livedata.get("/sys/livedata/pv_en"))
    net_kw    = _f(livedata.get("/sys/livedata/net_p"))        # + = importing from grid
    home_kw   = _f(livedata.get("/sys/livedata/site_load_p"))  # instantaneous home load

    if ld_pv_p  is not None: total_kw       = round(ld_pv_p, 3)
    if ld_pv_en is not None: total_kwh_life = round(ld_pv_en, 2)

    # ── Meters: production (suffix "p") and consumption / grid (suffix "c") ──
    prod_meter = next(
        (m for m in meters.values()
         if isinstance(m, dict) and str(m.get("prodMdlNm", "")).endswith("p")),
        {},
    )
    cons_meter = next(
        (m for m in meters.values()
         if isinstance(m, dict) and str(m.get("prodMdlNm", "")).endswith("c")),
        {},
    )
    grid_import_life = _f(cons_meter.get("posLtea3phsumKwh")) or 0.0
    grid_export_life = _f(cons_meter.get("negLtea3phsumKwh")) or 0.0
    grid_import_today = record_reading("__grid_import__", grid_import_life) if grid_import_life else 0.0
    grid_export_today = record_reading("__grid_export__", grid_export_life) if grid_export_life else 0.0
    grid_net_today    = round(grid_import_today - grid_export_today, 3)
    home_kwh_today    = round(max(0.0, total_kwh_today + grid_import_today - grid_export_today), 3)

    if home_kw is None and ld_pv_p is not None and net_kw is not None:
        home_kw = round(ld_pv_p + net_kw, 3)

    # ── CT-clamp correction ───────────────────────────────────────────────────
    # If home_kw is negative the consumption-meter CT is oriented backwards.
    # The magnitude is real grid export; true home load = PV − export.
    # Disable with ct_correction: false in config.json if your CTs are correct.
    ct_corrected = False
    if CT_CORRECTION and home_kw is not None and home_kw < -0.1:
        ct_corrected = True
        pv_ref = ld_pv_p if ld_pv_p is not None else total_kw
        corrected_export = round(home_kw * -1, 3)        # e.g. 5.75 kW
        home_kw = round((pv_ref or 0.0) + home_kw, 3)   # e.g. 8.0 − 5.75 = 2.25 kW
        if home_kw < 0:
            home_kw = 0.0
        net_kw = round(-corrected_export, 3)             # negative = exporting
        grid_direction = "export"

    if net_kw is None:
        grid_direction = "unknown"
    elif net_kw > 0.05:
        grid_direction = "import"
    elif net_kw < -0.05:
        grid_direction = "export"
    else:
        grid_direction = "idle"

    fwrev = sysinfo.get("/sys/info/fwrev", "—")
    supervisor = {
        "sw_rev": sysinfo.get("/sys/info/sw_rev", "—"),
        "hw_rev": sysinfo.get("/sys/info/hwrev", "—"),
        "fw_rev": fwrev.strip() if isinstance(fwrev, str) else "—",
        "mac":    sysinfo.get("/sys/info/lmac", "—"),
    }

    def _meter_snapshot(m):
        if not m:
            return None
        return {
            "model":          m.get("prodMdlNm"),
            "serial":         m.get("sn"),
            "power_kw":       _f(m.get("p3phsumKw")),
            "power_l1_kw":    _f(m.get("p1Kw")),
            "power_l2_kw":    _f(m.get("p2Kw")),
            "current_l1_a":   _f(m.get("i1A")),
            "current_l2_a":   _f(m.get("i2A")),
            "voltage_l1_v":   _f(m.get("v1nV")),
            "voltage_l2_v":   _f(m.get("v2nV")),
            "line_voltage_v": _f(m.get("v12V")),
            "freq_hz":        _f(m.get("freqHz")),
            "pf":             _f(m.get("totPfRto")),
            "ct_scale":       _f(m.get("ctSclFctr")),
            "apparent_kva":   _f(m.get("s3phsumKva")),
            "reactive_kvar":  _f(m.get("q3phsumKvar")),
            "net_lifetime_kwh":    _f(m.get("netLtea3phsumKwh")),
            "import_lifetime_kwh": _f(m.get("posLtea3phsumKwh")),
            "export_lifetime_kwh": _f(m.get("negLtea3phsumKwh")),
            "last_seen":      m.get("msmtEps"),
        }

    warnings = []
    cm_max_current = max(
        _f(cons_meter.get("i1A")) or 0.0,
        _f(cons_meter.get("i2A")) or 0.0,
    )
    pv_now = ld_pv_p if ld_pv_p is not None else total_kw

    if ct_corrected:
        warnings.append({
            "kind":   "ct_corrected",
            "title":  "CT clamp correction applied",
            "detail": "The consumption-meter CT clamp appears to be oriented backwards — the PVS "
                      "reported a negative home load. The dashboard has automatically corrected "
                      "this: grid export is derived from the raw reading and home load is "
                      "recalculated as Solar − Export. For accurate readings, physically "
                      "re-orient the CT clamp on the consumption meter.",
        })
    elif pv_now and pv_now > 2.0 and (home_kw is None or home_kw < 0.3):
        warnings.append({
            "kind":   "low_load",
            "title":  "Home load implausibly low",
            "detail": f"PV is producing {pv_now:.1f} kW but home_load reads {('%.2f' % home_kw) if home_kw is not None else '—'} kW. "
                      "Most homes have ≥0.3 kW baseline load (fridge, networking, standby). "
                      "If real loads are active, the CT clamps likely aren't capturing all circuits.",
        })
    elif pv_now and pv_now > 2.0 and cm_max_current < 3.0:
        warnings.append({
            "kind":   "ct_coverage",
            "title":  "Grid-meter current suspiciously low",
            "detail": f"Consumption-meter CTs read {cm_max_current:.1f} A max while PV is producing "
                      f"{pv_now:.1f} kW. If loads like EV charging or HVAC are active but not "
                      "reflected here, those circuits probably aren't passing through the CTs. "
                      "See the guide below.",
        })

    diagnostics = {
        "production_meter":  _meter_snapshot(prod_meter),
        "consumption_meter": _meter_snapshot(cons_meter),
        "livedata": {
            "pv_kw":        ld_pv_p,
            "net_kw":       net_kw,
            "site_load_kw": home_kw,
            "pv_lifetime_kwh":        ld_pv_en,
            "net_lifetime_kwh":       _f(livedata.get("/sys/livedata/net_en")),
            "site_load_lifetime_kwh": _f(livedata.get("/sys/livedata/site_load_en")),
        },
        "warnings": warnings,
    }

    return {
        "panels":     panels,
        "supervisor": supervisor,
        "summary": {
            "total_kw":         total_kw,
            "total_watts":      round(total_kw * 1000, 1),
            "kwh_today":        total_kwh_today,
            "kwh_lifetime":     total_kwh_life,
            "panel_count":      len(panels),
            "panels_online":    online,
            "panels_offline":   len(panels) - online,
            "home_kw":          None if home_kw is None else round(home_kw, 3),
            "home_watts":       None if home_kw is None else round(home_kw * 1000, 1),
            "home_kwh_today":   home_kwh_today,
            "ct_corrected":     ct_corrected,
            "grid_kw":          None if net_kw is None else round(net_kw, 3),
            "grid_watts":       None if net_kw is None else round(net_kw * 1000, 1),
            "grid_direction":   grid_direction,
            "grid_import_today": round(grid_import_today, 3),
            "grid_export_today": round(grid_export_today, 3),
            "grid_net_today":    grid_net_today,
            "grid_import_life":  round(grid_import_life, 2),
            "grid_export_life":  round(grid_export_life, 2),
        },
        "diagnostics": diagnostics,
        "fetched_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pvs_host":   BASE_URL,
    }


# ── Network settings ──────────────────────────────────────────────────────────
NETWORK_KEYS = [
    "/sys/info/ssid",
    "/sys/info/wpa_key",
    "/sys/info/active_interface",
    "/sys/info/active_interface_mac",
    "/net/sta0/state",
    "/net/wan0/state",
    "/net/wan1/state",
    "/net/wwan0/state",
    "/sys/toggle_cell/broadband_connected",
    "/sys/toggle_cell/cell_connected",
    "/sys/toggle_cell/low_data_mode",
]


def fetch_network():
    raw = {}
    for prefix in ("/sys/info", "/net", "/sys/toggle_cell"):
        try:
            raw.update(varserver_get(f"match={prefix}&fmt=obj"))
        except Exception:
            pass
    return {k: raw.get(k) for k in NETWORK_KEYS}


def write_var(path, value):
    """Attempt to write a varserver key. Returns (ok, status, message)."""
    if not _authenticated:
        login()
    url = f"{BASE_URL}/vars?set={path}&value={value}"
    resp = _session.post(url, data=b"", headers={"Content-Length": "0"}, timeout=15)
    try:
        body = resp.json()
    except Exception:
        body = {"description": resp.text[:200]}
    ok = resp.status_code == 200
    return ok, resp.status_code, body.get("description") or str(body)


# ── API routes ────────────────────────────────────────────────────────────────
@app.route("/api/network", methods=["GET"])
def api_network_get():
    try:
        values = fetch_network()
        if not is_tailscale_direct():
            values = dict(values)
            values["/sys/info/wpa_key"] = "••••••••" if values.get("/sys/info/wpa_key") else None
            values["/sys/info/active_interface_mac"] = _redact_str(
                values.get("/sys/info/active_interface_mac"))
        return jsonify({"ok": True, "values": values,
                        "note": "Local varserver API is read-only on firmware 2025.09+. "
                                "Change WiFi via the SunStrong mobile app (Bluetooth commissioning) "
                                "or the PVS hotspot setup page."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/data")
def api_data():
    try:
        data = fetch_all_data()
        if is_tailscale_direct():
            data["access"] = "trusted"
        else:
            data = redact_for_public(data)
        return jsonify({"ok": True, **data})
    except requests.exceptions.ConnectionError:
        return jsonify({"ok": False, "error": "connection_failed",
                        "pvs_host": BASE_URL,
                        "message": f"Could not reach PVS at {BASE_URL}."}), 503
    except PermissionError as e:
        return jsonify({"ok": False, "error": "auth_failed",
                        "pvs_host": BASE_URL, "message": str(e)}), 401
    except ValueError as e:
        return jsonify({"ok": False, "error": "no_password",
                        "pvs_host": BASE_URL, "message": str(e)}), 401
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/history")
def api_history():
    with _history_lock:
        data = _load_history()
        baselines = dict(data.get("baselines", {}))
        last_seen = dict(data.get("last_seen", {}))
    days = []
    for d in sorted(baselines.keys()):
        base = baselines[d]
        last = last_seen.get(d, {})
        panels = {}
        meta = {}
        for key, b in base.items():
            if key not in last:
                continue
            delta = round(max(0.0, last[key] - b), 3)
            if key.startswith("__"):
                meta[key.strip("_")] = delta
            else:
                panels[key] = delta
        pv_total    = round(sum(panels.values()), 2)
        grid_import = meta.get("grid_import", 0.0)
        grid_export = meta.get("grid_export", 0.0)
        home_kwh    = round(max(0.0, pv_total + grid_import - grid_export), 2)
        days.append({
            "date":            d,
            "total_kwh":       pv_total,
            "panels":          panels if is_tailscale_direct() else {},
            "home_kwh":        home_kwh,
            "grid_import_kwh": round(grid_import, 2),
            "grid_export_kwh": round(grid_export, 2),
            "grid_net_kwh":    round(grid_import - grid_export, 2),
        })
    return jsonify({"ok": True, "days": days})




# ── Dashboard ─────────────────────────────────────────────────────────────────
@app.route("/")
def dashboard():
    return render_template('dashboard.html')



if __name__ == "__main__":
    print("\n" + "─"*54)
    print("  ☀  SunPower / SunStrong Local Monitor  (varserver API)")
    print("─"*54)
    print(f"  PVS URL      : {BASE_URL}")
    print(f"  Password     : {'✓ set (' + str(len(PVS_PASSWORD)) + ' chars)' if PVS_PASSWORD else '✗ NOT SET'}")
    print(f"  CT correction: {'enabled' if CT_CORRECTION else 'disabled'}")
    print(f"  Dashboard    : http://localhost:{PORT}")
    print(f"  Auto-refresh every 30 seconds")
    if not PVS_PASSWORD:
        print("\n  ⚠  Set PVS_PASSWORD to the LAST 5 CHARS of the serial:")
        print("     PVS_HOST=192.168.x.x PVS_PASSWORD=XXXXX python3 sunpower_monitor.py")
    print("─"*54 + "\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)