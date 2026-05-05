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
from flask import Flask, jsonify, render_template_string, request

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
PVS_HOST     = os.environ.get("PVS_HOST",        _cfg.get("pvs_host",     "sunpowerlocal")).strip()
PVS_PASSWORD = os.environ.get("PVS_PASSWORD",    _cfg.get("pvs_password", "")).strip()
PORT         = int(os.environ.get("FLASK_RUN_PORT", _cfg.get("port",      5001)))

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
    ct_corrected = False
    if home_kw is not None and home_kw < -0.1:
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



# ── Dashboard HTML ────────────────────────────────────────────────────────────
DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SunPower Monitor</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=Syne:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0b0e12; --surface:#13181f; --border:#1e2730;
    --sun:#f5a623; --sun-dim:#7a4f0a;
    --green:#3dd68c; --green-dim:#0e3320;
    --red:#f25e5e; --red-dim:#3a0f0f;
    --blue:#4fb3ff; --blue-dim:#0a2a45;
    --muted:#4a5568; --text:#e2e8f0; --text-soft:#8899aa;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; min-height: 100vh; padding: 0 0 60px; }
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 32px; border-bottom: 1px solid var(--border);
    background: linear-gradient(180deg, rgba(245,166,35,0.06) 0%, transparent 100%);
  }
  .logo { display: flex; align-items: center; gap: 12px; }
  .logo-sun {
    width: 36px; height: 36px;
    background: radial-gradient(circle, var(--sun) 35%, transparent 70%);
    border-radius: 50%;
    box-shadow: 0 0 18px var(--sun), 0 0 40px rgba(245,166,35,0.3);
    animation: pulse-sun 3s ease-in-out infinite;
    flex-shrink: 0;
  }
  @keyframes pulse-sun {
    0%, 100% { box-shadow: 0 0 18px var(--sun), 0 0 40px rgba(245,166,35,0.3); }
    50%      { box-shadow: 0 0 28px var(--sun), 0 0 60px rgba(245,166,35,0.5); }
  }
  .logo-text { font-size: 1.15rem; font-weight: 800; letter-spacing: 0.05em; }
  .logo-sub  { font-size: 0.65rem; color: var(--text-soft); letter-spacing: 0.2em; text-transform: uppercase; }
  .header-right { text-align: right; }
  .refresh-btn {
    background: transparent; border: 1px solid var(--border);
    color: var(--text-soft);
    font-family: 'DM Mono', monospace; font-size: 0.72rem;
    padding: 6px 14px; border-radius: 6px;
    cursor: pointer; transition: all 0.2s; letter-spacing: 0.05em;
  }
  .refresh-btn:hover { border-color: var(--sun); color: var(--sun); }
  .refresh-btn.spinning { opacity: 0.5; pointer-events: none; }
  #last-updated { font-family: 'DM Mono', monospace; font-size: 0.65rem; color: var(--muted); margin-top: 4px; }

  .summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1px; background: var(--border);
    border-top: 1px solid var(--border); border-bottom: 1px solid var(--border);
    margin-bottom: 32px;
  }
  .stat-card { background: var(--surface); padding: 24px 28px; transition: background 0.2s; }
  .stat-card:hover { background: #161c25; }
  .stat-label { font-family: 'DM Mono', monospace; font-size: 0.65rem; letter-spacing: 0.18em; text-transform: uppercase; color: var(--text-soft); margin-bottom: 10px; }
  .stat-value { font-size: 2rem; font-weight: 800; line-height: 1; color: var(--text); }
  .stat-value.accent { color: var(--sun); }
  .stat-value.green  { color: var(--green); }
  .stat-value.blue   { color: var(--blue); }
  .stat-value.red    { color: var(--red); }
  .stat-unit { font-family: 'DM Mono', monospace; font-size: 0.7rem; color: var(--text-soft); margin-top: 4px; }
  .stat-arrow { margin-right: 6px; font-size: 1.4rem; vertical-align: -2px; }

  .flow-card {
    margin: 0 32px 32px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 24px; display: grid;
    grid-template-columns: 1fr auto 1fr auto 1fr; align-items: center; gap: 18px;
  }
  .flow-node { text-align: center; }
  .flow-icon { font-size: 1.8rem; margin-bottom: 6px; line-height: 1; }
  .flow-label { font-family: 'DM Mono', monospace; font-size: 0.62rem; color: var(--muted); letter-spacing: 0.18em; text-transform: uppercase; margin-bottom: 4px; }
  .flow-value { font-size: 1.4rem; font-weight: 800; line-height: 1; }
  .flow-unit { font-family: 'DM Mono', monospace; font-size: 0.58rem; color: var(--muted); margin-top: 3px; }
  .flow-arrow {
    font-family: 'DM Mono', monospace; font-size: 0.68rem;
    color: var(--text-soft); text-align: center;
    padding: 0 4px;
  }
  .flow-arrow .glyph { font-size: 1.3rem; color: var(--muted); display: block; margin-bottom: 2px; }
  .flow-arrow.active .glyph { color: var(--sun); }
  .flow-arrow.import .glyph { color: var(--red); }
  .flow-arrow.export .glyph { color: var(--green); }
  @media (max-width: 720px) {
    .flow-card { grid-template-columns: 1fr; }
    .flow-arrow { padding: 4px 0; }
    .flow-arrow .glyph { transform: rotate(90deg); }
  }

  .section-header { display: flex; align-items: center; gap: 12px; padding: 0 32px; margin-bottom: 20px; }
  .section-title { font-size: 0.7rem; font-family: 'DM Mono', monospace; letter-spacing: 0.2em; text-transform: uppercase; color: var(--text-soft); }
  .section-line { flex: 1; height: 1px; background: var(--border); }
  .badge { font-family: 'DM Mono', monospace; font-size: 0.62rem; padding: 2px 8px; border-radius: 3px; border: 1px solid; }
  .badge-ok   { color: var(--green); border-color: var(--green); background: var(--green-dim); }
  .badge-warn { color: var(--sun); border-color: var(--sun-dim); background: rgba(245,166,35,0.08); }

  .tabs {
    display: flex; gap: 2px; padding: 0 32px; border-bottom: 1px solid var(--border);
    background: var(--bg);
  }
  .tab-btn {
    background: transparent; border: none; border-bottom: 2px solid transparent;
    color: var(--text-soft); font-family: 'DM Mono', monospace;
    font-size: 0.72rem; letter-spacing: 0.15em; text-transform: uppercase;
    padding: 14px 20px; cursor: pointer; transition: all 0.2s;
    margin-bottom: -1px;
  }
  .tab-btn:hover { color: var(--text); }
  .tab-btn.active { color: var(--sun); border-bottom-color: var(--sun); }
  .tab { display: none; padding-top: 24px; }
  .tab.active { display: block; animation: fade-up 0.25s; }

  .hero {
    margin: 0 32px 28px; padding: 28px 32px;
    background: linear-gradient(135deg, rgba(79,179,255,0.08) 0%, rgba(245,166,35,0.05) 100%);
    border: 1px solid var(--border); border-radius: 12px;
    display: grid; grid-template-columns: 1fr auto; align-items: center; gap: 24px;
  }
  .hero-label {
    font-family: 'DM Mono', monospace; font-size: 0.68rem;
    letter-spacing: 0.2em; text-transform: uppercase; color: var(--text-soft);
    margin-bottom: 12px;
  }
  .hero-value {
    font-size: 4rem; font-weight: 800; line-height: 1; color: var(--blue);
    letter-spacing: -0.02em;
  }
  .hero-unit { font-family: 'DM Mono', monospace; font-size: 0.85rem; color: var(--text-soft); margin-top: 8px; letter-spacing: 0.15em; }
  .hero-side { display: flex; flex-direction: column; gap: 8px; min-width: 180px; }
  .hero-chip {
    font-family: 'DM Mono', monospace; font-size: 0.72rem;
    padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border);
    background: rgba(255,255,255,0.02);
    display: flex; justify-content: space-between; align-items: center; gap: 10px;
  }
  .hero-chip .k { color: var(--muted); letter-spacing: 0.1em; font-size: 0.62rem; text-transform: uppercase; }
  .hero-chip .v { color: var(--text); font-weight: 500; }
  .hero-chip.sun    .v { color: var(--sun); }
  .hero-chip.import .v { color: var(--red); }
  .hero-chip.export .v { color: var(--green); }
  @media (max-width: 640px) {
    .hero { grid-template-columns: 1fr; }
    .hero-value { font-size: 2.8rem; }
  }

  .panels-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 8px; padding: 0 32px; margin-bottom: 40px; }
  .panel-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 14px 16px;
    position: relative; transition: all 0.2s; overflow: hidden;
    opacity: 0; animation: fade-up 0.4s forwards;
  }
  .panel-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; border-radius: 8px 8px 0 0; }
  .panel-card.producing::before { background: var(--sun); }
  .panel-card.idle::before      { background: var(--muted); }
  .panel-card:hover { border-color: var(--sun-dim); transform: translateY(-1px); }
  .panel-serial { font-family: 'DM Mono', monospace; font-size: 0.65rem; color: var(--text-soft); letter-spacing: 0.1em; margin-bottom: 8px; }
  .panel-watts  { font-size: 1.5rem; font-weight: 800; line-height: 1; margin-bottom: 2px; }
  .panel-card.producing .panel-watts { color: var(--sun); }
  .panel-card.idle      .panel-watts { color: var(--muted); }
  .panel-unit { font-family: 'DM Mono', monospace; font-size: 0.6rem; color: var(--muted); }
  .panel-life { font-family: 'DM Mono', monospace; font-size: 0.6rem; color: var(--text-soft); margin-top: 8px; border-top: 1px solid var(--border); padding-top: 6px; }
  .panel-status-dot { position: absolute; top: 10px; right: 10px; width: 6px; height: 6px; border-radius: 50%; }
  .panel-card.producing .panel-status-dot { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .panel-card.idle      .panel-status-dot { background: var(--muted); }

  .supervisor-row { display: flex; flex-wrap: wrap; gap: 24px; padding: 0 32px; margin-bottom: 40px; }
  .sup-key { font-family: 'DM Mono', monospace; font-size: 0.6rem; color: var(--muted); letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 3px; }
  .sup-val { font-family: 'DM Mono', monospace; font-size: 0.8rem; color: var(--text-soft); }

  .net-card {
    margin: 0 32px 40px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px 24px;
  }
  .net-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
  .net-title { font-family: 'DM Mono', monospace; font-size: 0.72rem; letter-spacing: 0.2em; text-transform: uppercase; color: var(--text); }
  .net-sub   { font-family: 'DM Mono', monospace; font-size: 0.62rem; color: var(--muted); margin-top: 4px; letter-spacing: 0.1em; }
  .net-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 14px 28px;
  }
  .net-row .k { font-family: 'DM Mono', monospace; font-size: 0.6rem; color: var(--muted); letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 4px; }
  .net-row .v { font-family: 'DM Mono', monospace; font-size: 0.85rem; color: var(--text); word-break: break-all; }
  .net-row input {
    font-family: 'DM Mono', monospace; font-size: 0.82rem;
    background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 4px;
    padding: 5px 8px; width: 100%;
  }
  .net-row input:focus { outline: none; border-color: var(--sun); }
  .net-row input:disabled { color: var(--muted); border-style: dashed; }
  .net-actions { display: flex; gap: 8px; margin-top: 16px; align-items: center; flex-wrap: wrap; }
  .net-btn {
    background: transparent; border: 1px solid var(--border);
    color: var(--text-soft); font-family: 'DM Mono', monospace;
    font-size: 0.7rem; padding: 6px 14px; border-radius: 6px;
    cursor: pointer; letter-spacing: 0.05em; transition: all 0.2s;
  }
  .net-btn:hover:not(:disabled) { border-color: var(--sun); color: var(--sun); }
  .net-btn.primary { border-color: var(--sun-dim); color: var(--sun); background: rgba(245,166,35,0.08); }
  .net-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .net-msg { font-family: 'DM Mono', monospace; font-size: 0.7rem; padding: 8px 12px; border-radius: 4px; margin-top: 12px; line-height: 1.5; }
  .net-msg.info { color: var(--text-soft); background: rgba(255,255,255,0.03); border: 1px solid var(--border); }
  .net-msg.warn { color: var(--sun); background: rgba(245,166,35,0.06); border: 1px solid var(--sun-dim); }
  .net-msg.err  { color: var(--red); background: var(--red-dim); border: 1px solid var(--red); }
  .net-msg.ok   { color: var(--green); background: var(--green-dim); border: 1px solid var(--green); }

  .history-card {
    margin: 0 32px 40px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px 24px;
  }
  .hist-empty { font-family: 'DM Mono', monospace; font-size: 0.72rem; color: var(--muted); padding: 8px 0; }
  .hist-row {
    display: grid; grid-template-columns: 110px 1fr 90px;
    align-items: center; gap: 14px; padding: 8px 0;
    border-bottom: 1px solid var(--border);
    cursor: pointer;
  }
  .hist-row:last-child { border-bottom: none; }
  .hist-row:hover { background: rgba(255,255,255,0.02); }
  .hist-date { font-family: 'DM Mono', monospace; font-size: 0.72rem; color: var(--text-soft); letter-spacing: 0.08em; }
  .hist-date .today { color: var(--sun); }
  .hist-bar { height: 8px; background: var(--bg); border-radius: 4px; overflow: hidden; position: relative; }
  .hist-bar-fill { height: 100%; background: linear-gradient(90deg, var(--sun-dim), var(--sun)); border-radius: 4px; transition: width 0.3s; }
  .hist-val { font-family: 'DM Mono', monospace; font-size: 0.78rem; color: var(--text); text-align: right; }
  .hist-val .unit { color: var(--muted); font-size: 0.65rem; margin-left: 3px; }
  .hist-detail {
    grid-column: 1 / -1;
    padding: 12px 0 4px;
    display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
    gap: 6px 18px;
    font-family: 'DM Mono', monospace; font-size: 0.68rem; color: var(--text-soft);
  }
  .hist-detail .p-serial { color: var(--muted); margin-right: 6px; }
  .hist-meta {
    grid-column: 2 / 4;
    font-family: 'DM Mono', monospace; font-size: 0.62rem; color: var(--text-soft);
    display: flex; gap: 14px; margin-top: 2px; flex-wrap: wrap;
  }
  .hist-meta .used { color: var(--blue); }
  .hist-meta .imp  { color: var(--red); }
  .hist-meta .exp  { color: var(--green); }
  .hist-summary {
    display: flex; gap: 28px; padding-bottom: 12px; margin-bottom: 8px;
    border-bottom: 1px solid var(--border);
    font-family: 'DM Mono', monospace; font-size: 0.7rem; color: var(--text-soft);
  }
  .hist-summary b { color: var(--text); font-weight: 500; }

  .diag-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 16px; padding: 0 32px; margin-bottom: 24px;
  }
  .diag-meter {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 18px 20px;
  }
  .diag-meter-title {
    font-family: 'DM Mono', monospace; font-size: 0.75rem;
    letter-spacing: 0.18em; text-transform: uppercase; color: var(--text);
    margin-bottom: 4px;
  }
  .diag-meter-sub {
    font-family: 'DM Mono', monospace; font-size: 0.62rem;
    color: var(--muted); margin-bottom: 12px; letter-spacing: 0.08em;
  }
  .diag-table {
    width: 100%; border-collapse: collapse;
    font-family: 'DM Mono', monospace; font-size: 0.72rem;
  }
  .diag-table td {
    padding: 4px 0; border-bottom: 1px dotted var(--border);
    color: var(--text-soft);
  }
  .diag-table tr:last-child td { border-bottom: none; }
  .diag-table td:first-child { color: var(--muted); letter-spacing: 0.08em; }
  .diag-table td:last-child  { text-align: right; color: var(--text); }
  .diag-table td .muted { color: var(--muted); font-size: 0.6rem; margin-left: 4px; }

  .diag-warn, .diag-info {
    margin: 0 32px 16px; padding: 16px 20px;
    border: 1px solid; border-radius: 10px;
    font-family: 'DM Mono', monospace;
  }
  .diag-warn { background: rgba(242,94,94,0.06); border-color: var(--red); }
  .diag-info { background: rgba(79,179,255,0.04); border-color: var(--border); }
  .diag-warn-title {
    font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em;
    margin-bottom: 8px;
  }
  .diag-warn .diag-warn-title { color: var(--red); }
  .diag-info .diag-warn-title { color: var(--blue); }
  .diag-warn-body {
    font-size: 0.72rem; color: var(--text-soft); line-height: 1.6;
  }
  .diag-info ol { margin: 8px 0 0 20px; padding: 0; font-size: 0.72rem; color: var(--text-soft); line-height: 1.7; }
  .diag-info ol li { margin-bottom: 6px; }
  .diag-info b { color: var(--text); font-weight: 500; }
  .diag-info code { color: var(--sun); background: rgba(0,0,0,0.3); padding: 1px 5px; border-radius: 3px; }
  .diag-info .checklist { margin-top: 10px; padding: 10px 12px; background: rgba(0,0,0,0.2); border-radius: 6px; }
  .diag-info .checklist .t { color: var(--sun); letter-spacing: 0.1em; text-transform: uppercase; font-size: 0.62rem; margin-bottom: 6px; }

  .error-box { margin: 40px 32px; background: var(--red-dim); border: 1px solid var(--red); border-radius: 10px; padding: 28px 32px; }
  .error-title { color: var(--red); font-size: 1rem; font-weight: 700; margin-bottom: 12px; }
  .error-msg   { font-family: 'DM Mono', monospace; font-size: 0.78rem; color: var(--text-soft); line-height: 1.7; }
  .error-msg code { color: var(--sun); background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 3px; }

  #loading { display: flex; align-items: center; justify-content: center; height: 40vh; font-family: 'DM Mono', monospace; font-size: 0.8rem; color: var(--text-soft); letter-spacing: 0.15em; gap: 10px; }
  .spinner { width: 16px; height: 16px; border: 2px solid var(--border); border-top-color: var(--sun); border-radius: 50%; animation: spin 0.8s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes fade-up {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-sun"></div>
    <div>
      <div class="logo-text">SunPower Monitor</div>
      <div class="logo-sub">Local Network · varserver API</div>
    </div>
  </div>
  <div class="header-right">
    <div style="display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-bottom:4px;">
      <div id="access-badge" style="display:none;font-family:'DM Mono',monospace;font-size:0.62rem;color:var(--muted);padding:3px 10px;border:1px solid var(--border);border-radius:4px;letter-spacing:0.08em;">
        Public · read-only
      </div>
      <button class="refresh-btn" id="refresh-btn" onclick="load()">↻ Refresh</button>
    </div>
    <div id="last-updated">—</div>
  </div>
</header>

<nav class="tabs" id="tabs">
  <button class="tab-btn active" data-tab="overview" onclick="showTab('overview')">Overview</button>
  <button class="tab-btn"        data-tab="panels"   onclick="showTab('panels')">Panels</button>
  <button class="tab-btn"        data-tab="history"  onclick="showTab('history')">History</button>
  <button class="tab-btn"        data-tab="network"  onclick="showTab('network')">Network</button>
  <button class="tab-btn"        data-tab="diagnostics" onclick="showTab('diagnostics')">Diagnostics</button>
</nav>

<div id="app">
  <div id="loading"><div class="spinner"></div>CONNECTING TO PVS…</div>
</div>

<script>
let refreshTimer;
let currentTab = 'overview';
let accessLevel = 'trusted';
const fmt = (n, d = 1) => n == null ? '—' : Number(n).toFixed(d);
const escHtml = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

function showTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.id === 'tab-' + name);
  });
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === name);
  });
}

function render(data) {
  accessLevel = data.access || 'trusted';
  const badge = document.getElementById('access-badge');
  if (badge) badge.style.display = accessLevel === 'public' ? 'block' : 'none';
  if (!data.ok) {
    document.getElementById('app').innerHTML = `
      <div class="error-box">
        <div class="error-title">⚠ Could not connect to PVS</div>
        <div class="error-msg">
          Target: <code>${escHtml(data.pvs_host || '—')}</code><br><br>
          <b>Error:</b> ${escHtml(data.message || data.error)}<br><br>
          <b>Requirements (firmware 2025.09+):</b><br>
          1. <code>PVS_HOST</code> = IP of your PVS (e.g. <code>192.168.1.x</code>)<br>
          2. <code>PVS_PASSWORD</code> = <b>last 5 characters</b> of the serial number<br>
          3. PVS firmware build 61840+<br><br>
          Example:<br>
          <code>PVS_HOST=192.168.1.x PVS_PASSWORD=XXXXX python3 sunpower_monitor.py</code>
        </div>
      </div>`;
    return;
  }
  const s = data.summary, panels = data.panels, sup = data.supervisor;
  const badgeClass = s.panels_offline > 0 ? 'badge-warn' : 'badge-ok';
  const badgeText  = s.panels_offline > 0 ? `${s.panels_offline} idle` : 'all producing';

  const panelCards = panels.map((p, i) => {
    const cls = p.kw > 0 ? 'producing' : 'idle';
    return `
      <div class="panel-card ${cls}" style="animation-delay:${i*25}ms" title="${p.serial}">
        <div class="panel-status-dot"></div>
        <div class="panel-serial">${p.serial_short}</div>
        <div class="panel-watts">${p.kw > 0 ? fmt(p.kw, 3) : '—'}</div>
        <div class="panel-unit">kW</div>
        <div class="panel-life">
          ${p.kwh_today > 0 ? fmt(p.kwh_today, 2) + ' kWh today' : p.state}<br>
          ${fmt(p.kwh_life, 0)} kWh lifetime${p.temp_c != null ? ' · ' + p.temp_c + '°C' : ''}
        </div>
      </div>`;
  }).join('');

  const supBlock = sup && sup.sw_rev !== '—' ? `
    <div class="section-header">
      <span class="section-title">Supervisor</span>
      <div class="section-line"></div>
    </div>
    <div class="supervisor-row">
      <div><div class="sup-key">Firmware</div><div class="sup-val">${sup.sw_rev}</div></div>
      <div><div class="sup-key">Hardware</div><div class="sup-val">${sup.hw_rev}</div></div>
      <div><div class="sup-key">MAC</div><div class="sup-val">${sup.mac}</div></div>
    </div>` : '';

  const gridDir  = s.grid_direction;
  const gridLabel =
    gridDir === 'import' ? 'Importing' :
    gridDir === 'export' ? 'Exporting' :
    gridDir === 'idle'   ? 'Grid Idle' : 'Grid';
  const gridVerb =
    gridDir === 'import' ? 'Importing from grid' :
    gridDir === 'export' ? 'Exporting to grid' :
    gridDir === 'idle'   ? 'Grid idle' : 'Grid';
  const gridArrow =
    gridDir === 'import' ? '↓' :
    gridDir === 'export' ? '↑' : '';
  const gridClass =
    gridDir === 'import' ? 'red' :
    gridDir === 'export' ? 'green' : '';
  const gridChipClass =
    gridDir === 'import' ? 'import' :
    gridDir === 'export' ? 'export' : '';

  const pvKw     = s.total_kw || 0;
  const homeKw   = s.home_kw;
  const gridKw   = s.grid_kw;
  const gridAbs  = gridKw == null ? null : Math.abs(gridKw);

  const heroBlock = `
    <div class="hero">
      <div>
        <div class="hero-label">Home Using</div>
        <div class="hero-value">${homeKw == null ? '—' : fmt(homeKw, 2)}</div>
        <div class="hero-unit">KILOWATTS</div>
      </div>
      <div class="hero-side">
        <div class="hero-chip sun">
          <span class="k">Solar</span>
          <span class="v">${fmt(pvKw, 2)} kW</span>
        </div>
        <div class="hero-chip ${gridChipClass}">
          <span class="k">${gridVerb}</span>
          <span class="v">${gridAbs == null ? '—' : fmt(gridAbs, 2) + ' kW'}</span>
        </div>
      </div>
    </div>`;

  const flowBlock = (homeKw != null || gridKw != null) ? `
    <div class="flow-card">
      <div class="flow-node">
        <div class="flow-icon">☀</div>
        <div class="flow-label">Solar</div>
        <div class="flow-value" style="color:var(--sun)">${fmt(pvKw, 2)}</div>
        <div class="flow-unit">kW</div>
      </div>
      <div class="flow-arrow ${pvKw > 0.05 ? 'active' : ''}">
        <span class="glyph">→</span>
        ${pvKw > 0.05 ? fmt(Math.min(pvKw, homeKw || 0), 2) + ' kW' : '—'}
      </div>
      <div class="flow-node">
        <div class="flow-icon">🏠</div>
        <div class="flow-label">Home</div>
        <div class="flow-value" style="color:var(--blue)">${homeKw == null ? '—' : fmt(homeKw, 2)}</div>
        <div class="flow-unit">kW</div>
      </div>
      <div class="flow-arrow ${gridDir === 'export' ? 'export' : (gridDir === 'import' ? 'import' : '')}">
        <span class="glyph">${gridDir === 'export' ? '→' : (gridDir === 'import' ? '←' : '·')}</span>
        ${gridAbs != null && gridAbs > 0.05 ? fmt(gridAbs, 2) + ' kW' : '—'}
      </div>
      <div class="flow-node">
        <div class="flow-icon">⚡</div>
        <div class="flow-label">Grid</div>
        <div class="flow-value ${gridClass}">${gridAbs == null ? '—' : fmt(gridAbs, 2)}</div>
        <div class="flow-unit">${gridLabel.toUpperCase()}</div>
      </div>
    </div>` : '';

  const gridNetToday   = s.grid_net_today || 0;
  const gridTodayLabel = gridNetToday >= 0 ? 'Net Imported Today' : 'Net Exported Today';
  const gridTodayClass = gridNetToday >= 0 ? 'red' : 'green';

  const summaryBlock = `
    <div class="summary-grid">
      <div class="stat-card">
        <div class="stat-label">Now Producing</div>
        <div class="stat-value accent">${fmt(pvKw, 2)}</div>
        <div class="stat-unit">kW</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Home Using</div>
        <div class="stat-value blue">${homeKw == null ? '—' : fmt(homeKw, 2)}</div>
        <div class="stat-unit">kW</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">${gridLabel}</div>
        <div class="stat-value ${gridClass}">
          ${gridArrow ? `<span class="stat-arrow">${gridArrow}</span>` : ''}${gridAbs == null ? '—' : fmt(gridAbs, 2)}
        </div>
        <div class="stat-unit">kW</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Produced Today</div>
        <div class="stat-value accent">${fmt(s.kwh_today, 2)}</div>
        <div class="stat-unit">kWh</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Used Today</div>
        <div class="stat-value blue">${fmt(s.home_kwh_today, 2)}</div>
        <div class="stat-unit">kWh</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">${gridTodayLabel}</div>
        <div class="stat-value ${gridTodayClass}">${fmt(Math.abs(gridNetToday), 2)}</div>
        <div class="stat-unit">kWh · ↓${fmt(s.grid_import_today,1)} ↑${fmt(s.grid_export_today,1)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Lifetime Produced</div>
        <div class="stat-value">${fmt(s.kwh_lifetime, 0)}</div>
        <div class="stat-unit">kWh</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Panels Producing</div>
        <div class="stat-value green">${s.panels_online}<span style="font-size:1rem;color:var(--muted)"> / ${s.panel_count}</span></div>
        <div class="stat-unit">MICROINVERTERS</div>
      </div>
    </div>`;

  document.getElementById('app').innerHTML = `
    <div class="tab" id="tab-overview">
      ${heroBlock}
      ${flowBlock}
      ${summaryBlock}
    </div>

    <div class="tab" id="tab-panels">
      <div class="section-header">
        <span class="section-title">Panels</span>
        <div class="section-line"></div>
        <span class="badge ${badgeClass}">${badgeText}</span>
      </div>
      <div class="panels-grid">${panelCards}</div>
      ${supBlock}
    </div>

    <div class="tab" id="tab-history">
      <div class="section-header">
        <span class="section-title">History</span>
        <div class="section-line"></div>
      </div>
      <div class="history-card" id="history-card">
        <div class="hist-summary" id="hist-summary"></div>
        <div id="hist-rows"><div class="hist-empty">Loading…</div></div>
      </div>
    </div>

    <div class="tab" id="tab-diagnostics">
      <div class="section-header">
        <span class="section-title">Meter Diagnostics</span>
        <div class="section-line"></div>
      </div>
      <div id="diag-body"></div>
    </div>

    <div class="tab" id="tab-network">
      <div class="section-header">
        <span class="section-title">Network</span>
        <div class="section-line"></div>
      </div>
      <div class="net-card" id="net-card">
        <div class="net-header">
          <div>
            <div class="net-title">WiFi & Interfaces</div>
            <div class="net-sub">Source: PVS varserver · /sys/info · /net · /sys/toggle_cell</div>
          </div>
        </div>
        <div class="net-grid" id="net-grid"></div>
        <div class="net-msg" id="net-msg" style="display:none"></div>
      </div>
    </div>
  `;
  showTab(currentTab);
  loadNetwork();
  loadHistory();
  renderDiagnostics(data.diagnostics);
  document.getElementById('last-updated').textContent = 'Updated ' + data.fetched_at;
}

function renderDiagnostics(diag) {
  const el = document.getElementById('diag-body');
  if (!el) return;
  if (!diag) { el.innerHTML = '<div class="hist-empty" style="padding:0 32px">No diagnostic data.</div>'; return; }

  const warnings = (diag.warnings || []).map(w => `
    <div class="diag-warn">
      <div class="diag-warn-title">⚠ ${w.title}</div>
      <div class="diag-warn-body">${w.detail}</div>
    </div>`).join('');

  const row = (k, v) => `<tr><td>${k}</td><td>${v}</td></tr>`;
  const meterBlock = (m, role) => m ? `
    <div class="diag-meter">
      <div class="diag-meter-title">${role}</div>
      <div class="diag-meter-sub">${m.model || '—'} · ${m.serial || '—'}</div>
      <table class="diag-table">
        ${row('Total Power',    `${fmt(m.power_kw, 3)} kW`)}
        ${row('Leg 1 Power',    `${fmt(m.power_l1_kw, 3)} kW`)}
        ${row('Leg 2 Power',    `${fmt(m.power_l2_kw, 3)} kW`)}
        ${row('Leg 1 Current',  `${fmt(m.current_l1_a, 2)} A`)}
        ${row('Leg 2 Current',  `${fmt(m.current_l2_a, 2)} A`)}
        ${row('Leg 1 Voltage',  `${fmt(m.voltage_l1_v, 1)} V`)}
        ${row('Leg 2 Voltage',  `${fmt(m.voltage_l2_v, 1)} V`)}
        ${row('Line Voltage',   `${fmt(m.line_voltage_v, 1)} V`)}
        ${row('Frequency',      `${fmt(m.freq_hz, 2)} Hz`)}
        ${row('Power Factor',   `${fmt(m.pf, 3)}`)}
        ${row('CT Scale',       `${m.ct_scale ?? '—'}`)}
        ${row('Apparent',       `${fmt(m.apparent_kva, 3)} kVA`)}
        ${row('Reactive',       `${fmt(m.reactive_kvar, 3)} kVAR`)}
        ${m.net_lifetime_kwh != null    ? row('Net Lifetime',    `${fmt(m.net_lifetime_kwh, 1)} kWh`) : ''}
        ${m.import_lifetime_kwh         ? row('Import Lifetime', `${fmt(m.import_lifetime_kwh, 1)} kWh`) : ''}
        ${m.export_lifetime_kwh         ? row('Export Lifetime', `${fmt(m.export_lifetime_kwh, 1)} kWh`) : ''}
        ${row('Last Seen',      m.last_seen || '—')}
      </table>
    </div>` : '';

  const ld = diag.livedata || {};
  const ldBlock = `
    <div class="diag-meter">
      <div class="diag-meter-title">PVS Livedata (computed)</div>
      <div class="diag-meter-sub">/sys/livedata — derived by the PVS</div>
      <table class="diag-table">
        ${row('PV Power',       `${fmt(ld.pv_kw, 3)} kW`)}
        ${row('Net Grid Power', `${fmt(ld.net_kw, 3)} kW <span class="muted">(+ import, − export)</span>`)}
        ${row('Site Load',      `${fmt(ld.site_load_kw, 3)} kW`)}
        ${row('PV Lifetime',    `${fmt(ld.pv_lifetime_kwh, 1)} kWh`)}
        ${row('Net Lifetime',   `${fmt(ld.net_lifetime_kwh, 1)} kWh`)}
        ${row('Load Lifetime',  `${fmt(ld.site_load_lifetime_kwh, 1)} kWh`)}
      </table>
    </div>`;

  const guide = `
    <div class="diag-info">
      <div class="diag-warn-title">How to check for CT issues / hidden taps</div>
      <div class="diag-warn-body">
        The PVS only knows what the two <b>CT clamps</b> on the consumption meter tell it. If a load
        isn't passing through those CTs, the PVS will under-report home usage and grid flow.
      </div>
      <div class="checklist">
        <div class="t">At the main service panel (with an electrician, or cover off — no bare metal contact)</div>
        <ol>
          <li><b>Find the two CT clamps.</b> They're small white/gray plastic "donuts" (~1" wide) with thin
              twisted wires running back to the PVS6 enclosure. <b>There must be two</b>, one per hot leg.</li>
          <li><b>What are they clamped around?</b> Ideally each CT encircles one of the <b>two main service
              conductors</b> — the thick wires between the utility meter and the top lugs of the main breaker.
              If a CT is around a subfeed or a branch circuit, it only sees that circuit.</li>
          <li><b>Are they fully closed?</b> A CT that isn't latched shut reads near zero. Inspect the hinge.</li>
          <li><b>Orientation</b>: each CT has a printed arrow or <code>K→L</code> marking. <b>Both arrows must
              point the same direction</b> (toward the load). One flipped CT cancels out half the reading.</li>
          <li><b>Trace the EV breakers.</b> Standard double-pole 40–60 A breakers sitting in the main panel
              are downstream of the main breaker → CTs on the main conductors <b>should</b> see them. If yours
              don't, one of the above (1–4) is the likely culprit.</li>
          <li><b>Look for supply-side taps</b> (your case says unlikely, but confirm): Polaris connectors or
              an external enclosure with thick wires between the utility meter and the panel that doesn't
              pass through the CT clamps.</li>
        </ol>
      </div>
      <div class="checklist">
        <div class="t">If you're taking a video — capture these shots, slowly</div>
        <ol>
          <li>Dead-cover off: top of the panel where the service enters, clearly showing the <b>main breaker
              lugs</b> and both CT clamps (close-up on what conductor each is wrapped around).</li>
          <li>Pan down the breaker column so every breaker label is legible — especially the EV charger breakers.</li>
          <li>The thin CT wires traced from the clamps to where they exit the panel and enter the PVS6 box.</li>
          <li>The exterior utility meter socket plus any subpanels or separate enclosures nearby — from
              outside, zoom the conductor path from meter → main panel.</li>
          <li>Inside the PVS6 box: the CT inputs terminals (two pairs), to verify both CTs are actually
              connected and not loose.</li>
        </ol>
      </div>
      <div class="diag-warn-body" style="margin-top:12px">
        <b>Quick sanity check while you're there:</b> plug a known 1500 W load (electric kettle, heater)
        into an outlet and watch this page. <b>Leg 1 / Leg 2 Current</b> above should jump by ~6 A on the
        leg the outlet is on. If it doesn't budge, that outlet's branch isn't routed through the CTs.
      </div>
    </div>`;

  el.innerHTML = `
    ${warnings}
    <div class="diag-grid">
      ${meterBlock(diag.production_meter,  'Production Meter')}
      ${meterBlock(diag.consumption_meter, 'Consumption / Grid Meter')}
      ${ldBlock}
    </div>
    ${guide}
  `;
}

async function load() {
  const btn = document.getElementById('refresh-btn');
  btn.classList.add('spinning');
  clearTimeout(refreshTimer);
  try {
    const res = await fetch('/api/data');
    render(await res.json());
  } catch (e) {
    render({ ok: false, error: e.message, pvs_host: 'unknown' });
  } finally {
    btn.classList.remove('spinning');
    refreshTimer = setTimeout(load, 30000);
  }
}

load();

// ── History ──────────────────────────────────────────────────────────────
const expandedDays = new Set();

function fmtDate(iso) {
  const [y,m,d] = iso.split('-').map(Number);
  const dt = new Date(y, m - 1, d);
  const today = new Date();
  today.setHours(0,0,0,0);
  const diffDays = Math.round((today - dt) / 86400000);
  const wk = dt.toLocaleDateString(undefined, { weekday: 'short' });
  const md = dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  if (diffDays === 0)  return `<span class="today">TODAY</span> · ${md}`;
  if (diffDays === 1)  return `YESTERDAY · ${md}`;
  return `${wk.toUpperCase()} · ${md}`;
}

function renderHistory(days) {
  const rowsEl  = document.getElementById('hist-rows');
  const sumEl   = document.getElementById('hist-summary');
  if (!days.length) {
    rowsEl.innerHTML = '<div class="hist-empty">No history yet — the monitor builds this up as it runs each day.</div>';
    sumEl.innerHTML = '';
    return;
  }
  const totalAll = days.reduce((a,d) => a + d.total_kwh, 0);
  const last30   = days.slice(-30);
  const avg30    = last30.length ? last30.reduce((a,d)=>a+d.total_kwh,0) / last30.length : 0;
  const best     = days.reduce((m,d) => d.total_kwh > m.total_kwh ? d : m, days[0]);
  const max      = Math.max(...days.map(d => d.total_kwh), 0.1);

  sumEl.innerHTML = `
    <div><b>${days.length}</b> days recorded</div>
    <div>30-day avg: <b>${avg30.toFixed(1)} kWh</b></div>
    <div>Best: <b>${best.total_kwh.toFixed(1)} kWh</b> (${best.date})</div>
    <div>All-time: <b>${totalAll.toFixed(0)} kWh</b></div>
  `;

  const desc = [...days].reverse();
  rowsEl.innerHTML = desc.map(d => {
    const pct = Math.max(1, (d.total_kwh / max) * 100);
    const panelList = Object.entries(d.panels)
      .sort((a,b) => b[1] - a[1])
      .map(([s,kwh]) => `<div><span class="p-serial">${s.slice(-6)}</span>${kwh.toFixed(2)} kWh</div>`)
      .join('');
    const expanded = expandedDays.has(d.date);
    const hasMeter = (d.grid_import_kwh || 0) + (d.grid_export_kwh || 0) > 0;
    const metaLine = hasMeter ? `
      <div class="hist-meta">
        <span class="used">Used ${(d.home_kwh || 0).toFixed(2)} kWh</span>
        <span class="imp">↓ ${(d.grid_import_kwh || 0).toFixed(2)}</span>
        <span class="exp">↑ ${(d.grid_export_kwh || 0).toFixed(2)}</span>
      </div>` : '';
    return `
      <div class="hist-row" onclick="toggleHistDay('${d.date}')">
        <div class="hist-date">${fmtDate(d.date)}</div>
        <div class="hist-bar"><div class="hist-bar-fill" style="width:${pct}%"></div></div>
        <div class="hist-val">${d.total_kwh.toFixed(2)}<span class="unit">kWh</span></div>
        ${metaLine}
        ${expanded ? `<div class="hist-detail">${panelList || '<div class="hist-empty">No per-panel data.</div>'}</div>` : ''}
      </div>`;
  }).join('');
}

function toggleHistDay(d) {
  if (expandedDays.has(d)) expandedDays.delete(d);
  else expandedDays.add(d);
  loadHistory();
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const d = await res.json();
    if (d.ok) renderHistory(d.days || []);
  } catch (e) {
    document.getElementById('hist-rows').innerHTML =
      `<div class="hist-empty">History load failed: ${e.message}</div>`;
  }
}

// ── Network settings ─────────────────────────────────────────────────────
const NET_LABELS = {
  "/sys/info/ssid":                       "SSID",
  "/sys/info/wpa_key":                    "WPA Key",
  "/sys/info/active_interface":           "Active Interface",
  "/sys/info/active_interface_mac":       "Interface MAC",
  "/net/sta0/state":                      "WiFi (sta0)",
  "/net/wan0/state":                      "WAN0",
  "/net/wan1/state":                      "WAN1",
  "/net/wwan0/state":                     "Cellular",
  "/sys/toggle_cell/broadband_connected": "Broadband",
  "/sys/toggle_cell/cell_connected":      "Cell Connected",
  "/sys/toggle_cell/low_data_mode":       "Low Data Mode",
};

let netCurrent = {};

function netMsg(kind, text) {
  const el = document.getElementById('net-msg');
  el.className = 'net-msg ' + kind;
  el.textContent = text;
  el.style.display = 'block';
}

function renderNet() {
  const grid = document.getElementById('net-grid');
  grid.innerHTML = Object.keys(NET_LABELS).map(k => {
    const v = netCurrent[k];
    const display = v == null ? '—' : v;
    return `<div class="net-row"><div class="k">${NET_LABELS[k]}</div><div class="v">${display}</div></div>`;
  }).join('');
}

async function loadNetwork() {
  try {
    const res = await fetch('/api/network');
    const d = await res.json();
    if (!d.ok) { netMsg('err', d.message || d.error || 'Failed to load'); return; }
    netCurrent = d.values || {};
    renderNet();
    if (d.note) netMsg('info', d.note);
  } catch (e) {
    netMsg('err', 'Network fetch failed: ' + e.message);
  }
}

</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD)


if __name__ == "__main__":
    print("\n" + "─"*54)
    print("  ☀  SunPower / SunStrong Local Monitor  (varserver API)")
    print("─"*54)
    print(f"  PVS URL    : {BASE_URL}")
    print(f"  Password   : {'✓ set (' + str(len(PVS_PASSWORD)) + ' chars)' if PVS_PASSWORD else '✗ NOT SET'}")
    print(f"  Dashboard  : http://localhost:{PORT}")
    print(f"  Auto-refresh every 30 seconds")
    if not PVS_PASSWORD:
        print("\n  ⚠  Set PVS_PASSWORD to the LAST 5 CHARS of the serial:")
        print("     PVS_HOST=192.168.x.x PVS_PASSWORD=XXXXX python3 sunpower_monitor.py")
    print("─"*54 + "\n")
    app.run(host="0.0.0.0", port=PORT, debug=False)