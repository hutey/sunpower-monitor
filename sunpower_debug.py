#!/usr/bin/env python3
"""
sunpower_debug.py — SunPower Monitor diagnostic tool

Usage:
  python3 sunpower_debug.py                   # auto-loads config.json, SSH + API checks
  python3 sunpower_debug.py --host URL        # API checks only (no SSH)
  python3 sunpower_debug.py --ssh             # SSH into Pi for logs/service/PVS check
  python3 sunpower_debug.py --local           # run directly ON the Pi
  python3 sunpower_debug.py --logs [N]        # show last N journal lines (default 60)
  python3 sunpower_debug.py --history         # detailed history.json gap report
  python3 sunpower_debug.py --pvs             # direct PVS varserver probe (local/SSH)
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import textwrap
import time
from datetime import date, timedelta
from pathlib import Path

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── Colour helpers ────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[31m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
DIM    = "\033[2m"

def ok(msg):    print(f"  {GREEN}✅{RESET}  {msg}")
def warn(msg):  print(f"  {YELLOW}⚠️ {RESET}  {msg}")
def err(msg):   print(f"  {RED}✗{RESET}   {msg}")
def info(msg):  print(f"  {CYAN}ℹ{RESET}   {msg}")
def head(msg):  print(f"\n{BOLD}{CYAN}{msg}{RESET}\n{'─'*54}")
def dim(msg):   print(f"  {DIM}{msg}{RESET}")


# ── Config loading ────────────────────────────────────────────────────────────
def load_config():
    cfg_path = Path(__file__).parent / "config.json"
    if cfg_path.exists():
        try:
            with open(cfg_path) as f:
                return json.load(f)
        except Exception as e:
            warn(f"Could not parse config.json: {e}")
    return {}


# ── SSH helper ────────────────────────────────────────────────────────────────
def ssh_run(host, user, cmd, timeout=30, _ssh_cmd=None):
    """Run a shell command on the Pi via SSH. Returns (stdout, stderr, returncode)."""
    if _ssh_cmd is None:
        _ssh_cmd = _SSH_CMD
    full = _ssh_cmd + [f"{user}@{host}", cmd]
    try:
        result = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "SSH timed out", 1
    except FileNotFoundError:
        return "", "ssh not found in PATH", 1


# Probe which SSH method works: prefer Tailscale SSH, fall back to OpenSSH IPv4
_SSH_CMD = ["ssh", "-4", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]

def _detect_ssh(host, user):
    """Try Tailscale SSH first, then regular SSH. Return the working command or None."""
    global _SSH_CMD

    # 1. Try tailscale ssh (bypasses sshd, works even if sshd is broken)
    ts_cmd = ["tailscale", "ssh", "--timeout=10s"]
    out, err2, rc = ssh_run(host, user, "echo ok", _ssh_cmd=ts_cmd)
    if rc == 0:
        print(f"  {CYAN}ℹ{RESET}   Using Tailscale SSH")
        _SSH_CMD = ts_cmd
        return ts_cmd

    # 2. Regular SSH, IPv4 forced
    std_cmd = ["ssh", "-4", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no"]
    out, err2, rc = ssh_run(host, user, "echo ok", _ssh_cmd=std_cmd)
    if rc == 0:
        _SSH_CMD = std_cmd
        return std_cmd

    return None


def ssh_reachable(host, user):
    return _detect_ssh(host, user) is not None


# ── API checks (remote) ───────────────────────────────────────────────────────
def check_api(base_url, timeout=15):
    if not HAS_REQUESTS:
        err("requests library not installed — skipping API checks")
        return None

    head("API checks")
    results = {}

    for path, label in [("/api/data", "Live data"), ("/api/history", "History"), ("/api/network", "Network")]:
        url = base_url.rstrip("/") + path
        try:
            t0 = time.time()
            r = requests.get(url, timeout=timeout)
            elapsed = round((time.time() - t0) * 1000)
            body = r.json()
            if r.status_code == 200 and body.get("ok"):
                ok(f"{label:14s} {r.status_code}  ({elapsed} ms)")
                results[path] = body
            else:
                err(f"{label:14s} {r.status_code}  ({elapsed} ms)  error={body.get('error','?')}  msg={body.get('message','')}")
                results[path] = body
        except requests.exceptions.ConnectionError:
            err(f"{label:14s} CONNECTION REFUSED — is the service running on port 5001?")
            results[path] = None
        except requests.exceptions.Timeout:
            err(f"{label:14s} TIMEOUT after {timeout}s")
            results[path] = None
        except Exception as e:
            err(f"{label:14s} {e}")
            results[path] = None

    return results


def print_live_summary(data):
    if not data or not data.get("ok"):
        return
    head("Live snapshot")
    s = data.get("summary", {})
    sup = data.get("supervisor", {})
    diag = data.get("diagnostics", {})

    info(f"Fetched at      : {data.get('fetched_at', '—')}")
    info(f"Total solar     : {s.get('total_kw', '—')} kW  ({s.get('total_watts', '—')} W)")
    info(f"Home load       : {s.get('home_kw', '—')} kW")
    info(f"Grid            : {s.get('grid_kw', '—')} kW  ({s.get('grid_direction', '—')})")
    info(f"Today           : {s.get('kwh_today', '—')} kWh  |  Lifetime: {s.get('kwh_lifetime', '—')} kWh")
    info(f"Panels          : {s.get('panels_online', '—')} online / {s.get('panel_count', '—')} total")
    info(f"Firmware        : {sup.get('fw_rev', '—')}  SW: {sup.get('sw_rev', '—')}")
    if s.get("ct_corrected"):
        warn("CT clamp correction is active (consumption meter CT may be backwards)")

    warnings = diag.get("warnings", [])
    for w in warnings:
        warn(f"{w.get('title', '')}: {w.get('detail', '')[:120]}")


def print_history_summary(data, detailed=False):
    if not data or not data.get("ok"):
        return
    head("History summary")
    days = data.get("days", [])
    if not days:
        warn("No history data returned")
        return

    all_dates = {d["date"] for d in days}
    first = min(all_dates)
    last  = max(all_dates)
    info(f"Range           : {first} → {last}  ({len(days)} days recorded)")

    # Gap detection
    gaps = []
    cur = date.fromisoformat(first)
    end = date.fromisoformat(last)
    while cur <= end:
        if cur.isoformat() not in all_dates:
            gaps.append(cur.isoformat())
        cur += timedelta(days=1)

    if gaps:
        err(f"Gaps found      : {len(gaps)} missing day(s)")
        for g in gaps[-10:]:
            dim(f"    {g}")
        if len(gaps) > 10:
            dim(f"    … and {len(gaps)-10} more")
    else:
        ok(f"No gaps in history range")

    # Last 7 days
    recent = sorted(days, key=lambda d: d["date"])[-7:]
    print()
    print(f"  {'Date':<12} {'Solar':>8} {'Home':>8} {'Import':>8} {'Export':>8}")
    print(f"  {'─'*12} {'─'*8} {'─'*8} {'─'*8} {'─'*8}")
    for d in recent:
        solar  = f"{d['total_kwh']:.2f}" if d.get('total_kwh') is not None else "—"
        home   = f"{d['home_kwh']:.2f}" if d.get('home_kwh') is not None else "—"
        imp    = f"{d['grid_import_kwh']:.2f}" if d.get('grid_import_kwh') is not None else "—"
        exp    = f"{d['grid_export_kwh']:.2f}" if d.get('grid_export_kwh') is not None else "—"
        print(f"  {d['date']:<12} {solar:>8} {home:>8} {imp:>8} {exp:>8}")


# ── SSH-based Pi checks ───────────────────────────────────────────────────────
def check_ssh(host, user, cfg, log_lines=60):
    head(f"Pi system checks  ({user}@{host})")

    if not ssh_reachable(host, user):
        err(f"Cannot SSH to {user}@{host} — Pi unreachable or SSH down")
        return

    ok(f"SSH reachable   : {user}@{host}")

    # systemd service status
    stdout, _, rc = ssh_run(host, user, "systemctl is-active sunpower 2>/dev/null")
    state = stdout.strip()
    if state == "active":
        ok(f"Service status  : {state}")
        stdout2, _, _ = ssh_run(host, user, "systemctl show sunpower --property=ActiveEnterTimestamp --value 2>/dev/null")
        info(f"  Running since : {stdout2.strip()}")
    else:
        err(f"Service status  : {state or 'unknown'}")
        stdout2, _, _ = ssh_run(host, user, "systemctl status sunpower --no-pager -l 2>&1 | tail -20")
        print(textwrap.indent(stdout2, "    "))

    # Disk
    stdout, _, _ = ssh_run(host, user, "df -h / 2>/dev/null | tail -1")
    parts = stdout.split()
    if len(parts) >= 5:
        used_pct = int(parts[4].rstrip('%'))
        msg = f"Disk /          : {parts[2]} used / {parts[1]} total  ({parts[4]} full)"
        if used_pct > 85:
            err(msg)
        elif used_pct > 70:
            warn(msg)
        else:
            ok(msg)

    # Memory
    stdout, _, _ = ssh_run(host, user, "free -h 2>/dev/null | awk '/^Mem/{print $3\"/\"$2}'")
    info(f"Memory          : {stdout.strip()}")

    # Uptime
    stdout, _, _ = ssh_run(host, user, "uptime -p 2>/dev/null")
    info(f"Uptime          : {stdout.strip()}")

    # Tailscale
    stdout, _, rc = ssh_run(host, user, "tailscale status --self 2>/dev/null | head -1")
    if rc == 0 and stdout.strip():
        ok(f"Tailscale       : {stdout.strip()}")
    else:
        warn("Tailscale       : not running or not installed")

    # Python / gunicorn process
    stdout, _, _ = ssh_run(host, user,
        "ps aux 2>/dev/null | grep -E 'gunicorn|sunpower' | grep -v grep | head -3")
    if stdout.strip():
        ok(f"Process running :")
        for line in stdout.strip().splitlines():
            dim(f"    {line[:100]}")
    else:
        err("No gunicorn/sunpower process found")

    # Port listening
    stdout, _, _ = ssh_run(host, user,
        "ss -tlnp 2>/dev/null | grep ':5001' || netstat -tlnp 2>/dev/null | grep ':5001'")
    if stdout.strip():
        ok(f"Port 5001       : listening")
    else:
        err("Port 5001       : NOT listening")


def check_logs(host, user, n=60):
    head(f"Journal logs  (last {n} lines)")
    stdout, stderr, rc = ssh_run(
        host, user,
        f"journalctl -u sunpower -n {n} --no-pager --output=short-iso 2>&1",
        timeout=20,
    )
    if rc != 0 or not stdout.strip():
        # fallback: try reading log file directly
        stdout2, _, _ = ssh_run(host, user,
            "find /var/log /home -name 'sunpower*.log' 2>/dev/null | head -1 | xargs tail -60 2>/dev/null")
        if stdout2.strip():
            print(textwrap.indent(stdout2, "  "))
        else:
            err(f"Could not retrieve logs: {stderr.strip() or 'no output'}")
        return

    lines = stdout.strip().splitlines()
    # Highlight errors/warnings
    for line in lines:
        lower = line.lower()
        if any(k in lower for k in ("error", "traceback", "exception", "critical", "500")):
            print(f"  {RED}{line}{RESET}")
        elif any(k in lower for k in ("warn", "warning")):
            print(f"  {YELLOW}{line}{RESET}")
        else:
            dim(line)


def check_pvs_direct(host, user, cfg):
    """SSH into Pi and do a direct HTTPS probe of the PVS varserver."""
    head("Direct PVS probe  (via Pi)")

    pvs_host = cfg.get("pvs_host", "sunpowerlocal")
    for prefix in ("https://", "http://"):
        if pvs_host.startswith(prefix):
            pvs_host = pvs_host[len(prefix):]
    pvs_host = pvs_host.rstrip("/")
    pvs_pass = cfg.get("pvs_password", "")

    if not pvs_pass:
        warn("pvs_password not set in config.json — skipping direct PVS probe")
        return

    auth_b64 = base64.b64encode(f"ssm_owner:{pvs_pass}".encode()).decode()

    # Write credential to a per-session temp file on the Pi so it never appears
    # in ps aux / shell history. Cleaned up at the end of this function.
    setup_cmd = (
        "CRED_FILE=$(mktemp /tmp/.pvs_cred_XXXXXX) && "
        f"chmod 600 \"$CRED_FILE\" && "
        f"echo 'Authorization: basic {auth_b64}' > \"$CRED_FILE\" && "
        "echo $CRED_FILE"
    )
    cred_out, _, rc = ssh_run(host, user, setup_cmd)
    cred_file = cred_out.strip()
    if not cred_file or rc != 0:
        err("PVS probe: could not create credential temp file on Pi")
        return

    def _pvs_curl(url, extra=""):
        """Run curl on the Pi using the credential file (auth header not in ps aux)."""
        return ssh_run(host, user,
            f"curl -sk --max-time 10 -H @\"{cred_file}\" {extra} '{url}' 2>/dev/null")

    def _cleanup():
        ssh_run(host, user, f"rm -f \"{cred_file}\"")

    # Test HTTPS reachability
    ping_cmd = (
        f"curl -sk --max-time 10 -o /dev/null -w '%{{http_code}}' "
        f"https://{pvs_host}/ 2>/dev/null"
    )
    stdout, _, rc = ssh_run(host, user, ping_cmd)
    code = stdout.strip()
    if code in ("200", "301", "302", "401"):
        ok(f"PVS HTTPS       : reachable (HTTP {code})")
    else:
        err(f"PVS HTTPS       : unreachable (got '{code}', rc={rc})")
        info(f"PVS host        : https://{pvs_host}")
        _cleanup()
        return

    # Test auth + varserver
    stdout, _, rc = _pvs_curl(f"https://{pvs_host}/auth?login")
    try:
        body = json.loads(stdout)
        if "session" in body:
            ok("PVS auth        : login OK")
        else:
            err(f"PVS auth        : unexpected response: {stdout[:120]}")
            _cleanup()
            return
    except Exception:
        err(f"PVS auth        : could not parse response: {stdout[:120]}")
        _cleanup()
        return

    # Quick varserver read
    var_stdout, _, rc = _pvs_curl(
        f"https://{pvs_host}/vars?match=inverter&fmt=obj",
        extra="| python3 -c \"import json,sys; d=json.load(sys.stdin); "
              "keys=[k for k in d if 'pMppt1Kw' in k]; "
              "print(len(keys),'inverters found'); "
              "[print(' ',k,'=',d[k]) for k in keys[:3]]\"",
    )
    stdout, rc = var_stdout, rc
    _cleanup()
    if stdout.strip():
        ok(f"PVS varserver   : {stdout.strip().splitlines()[0]}")
        for line in stdout.strip().splitlines()[1:]:
            dim(f"    {line}")
    else:
        warn("PVS varserver   : no inverter data returned (PV may be offline / night)")


def check_history_local(history_path):
    head("History analysis  (local)")
    p = Path(history_path)
    if not p.exists():
        err(f"history.json not found at {p}")
        return

    size_kb = round(p.stat().st_size / 1024, 1)
    info(f"File size       : {size_kb} KB")

    try:
        with open(p) as f:
            data = json.load(f)
    except Exception as e:
        err(f"Cannot parse history.json: {e}")
        return

    baselines = data.get("baselines", {})
    last_seen = data.get("last_seen", {})
    all_dates = sorted(set(list(baselines.keys()) + list(last_seen.keys())))

    if not all_dates:
        warn("history.json is empty")
        return

    first, last = all_dates[0], all_dates[-1]
    info(f"Range           : {first} → {last}  ({len(all_dates)} days)")

    gaps = []
    cur = date.fromisoformat(first)
    end = date.fromisoformat(last)
    while cur <= end:
        if cur.isoformat() not in set(all_dates):
            gaps.append(cur.isoformat())
        cur += timedelta(days=1)

    if gaps:
        err(f"Gaps            : {len(gaps)} missing day(s)")
        for g in gaps:
            dim(f"    {g}")
    else:
        ok(f"No gaps in history range")

    # Last 7 days detail
    print()
    print(f"  {'Date':<12} {'Solar kWh':>10} {'Import':>8} {'Export':>8} {'Panels':>7}")
    print(f"  {'─'*12} {'─'*10} {'─'*8} {'─'*8} {'─'*7}")
    for d in all_dates[-7:]:
        b = baselines.get(d, {})
        l = last_seen.get(d, {})
        pv_serials = [k for k in b if not k.startswith("__")]
        pv_total   = sum(max(0, l.get(k, b[k]) - b[k]) for k in pv_serials)
        gi = max(0, l.get("__grid_import__", b.get("__grid_import__", 0)) - b.get("__grid_import__", 0))
        ge = max(0, l.get("__grid_export__", b.get("__grid_export__", 0)) - b.get("__grid_export__", 0))
        print(f"  {d:<12} {pv_total:>10.3f} {gi:>8.3f} {ge:>8.3f} {len(pv_serials):>7}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SunPower Monitor — debug tool")
    parser.add_argument("--host",    metavar="URL",
                        help="Flask base URL for API checks (e.g. http://sunpower-pi:5001)")
    parser.add_argument("--ssh",     action="store_true",
                        help="SSH into Pi for system + log checks")
    parser.add_argument("--local",   action="store_true",
                        help="Run directly on the Pi (reads history.json, checks local API)")
    parser.add_argument("--logs",    nargs="?", const=60, type=int, metavar="N",
                        help="Show last N journal log lines (default 60)")
    parser.add_argument("--history", action="store_true",
                        help="Detailed history gap report")
    parser.add_argument("--pvs",     action="store_true",
                        help="Direct PVS varserver probe")
    parser.add_argument("--pi-host", metavar="HOST",  help="Override Pi hostname/IP")
    parser.add_argument("--pi-user", metavar="USER",  help="Override Pi SSH user")
    args = parser.parse_args()

    cfg  = load_config()
    pi_host = args.pi_host or cfg.get("pi_host", "pisunpower.local")
    pi_user = args.pi_user or cfg.get("pi_user", "pi")
    port    = cfg.get("port", 5001)

    # Default behaviour: if no flags given, run everything we can
    run_all = not any([args.host, args.ssh, args.local, args.logs is not None,
                       args.history, args.pvs])

    print(f"\n{BOLD}{'═'*54}")
    print(f"  ☀  SunPower Debug Report  —  {date.today()}")
    print(f"{'═'*54}{RESET}")

    # ── Determine API base URL ────────────────────────────────────────────────
    api_base = args.host
    if not api_base and args.local:
        api_base = f"http://localhost:{port}"
    if not api_base and (run_all or args.ssh):
        # Try Pi local hostname first; fall back to localhost if running on Pi
        api_base = f"http://{pi_host}:{port}"

    # ── API checks ────────────────────────────────────────────────────────────
    api_results = None
    if api_base and (run_all or args.host or args.local or args.ssh):
        api_results = check_api(api_base)
        if api_results:
            live = api_results.get("/api/data")
            hist = api_results.get("/api/history")
            if live:
                print_live_summary(live)
            if hist and (run_all or args.history):
                print_history_summary(hist, detailed=args.history)

    # ── SSH-based checks ──────────────────────────────────────────────────────
    if run_all or args.ssh or args.logs is not None or args.pvs:
        if args.local:
            info("--local mode: skipping SSH checks")
        else:
            check_ssh(pi_host, pi_user, cfg)

            n_logs = args.logs if args.logs is not None else (60 if run_all else None)
            if n_logs is not None:
                check_logs(pi_host, pi_user, n=n_logs)

            if run_all or args.pvs:
                check_pvs_direct(pi_host, pi_user, cfg)

    # ── Local history check ───────────────────────────────────────────────────
    if args.local or args.history:
        history_path = Path(__file__).parent / "history.json"
        if history_path.exists():
            check_history_local(history_path)
        else:
            warn(f"history.json not found locally — use --ssh for remote check")

    print(f"\n{DIM}{'─'*54}{RESET}\n")


if __name__ == "__main__":
    main()
