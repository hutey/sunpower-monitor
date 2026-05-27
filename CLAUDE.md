# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run the monitor (local dev)
python3 sunpower_monitor.py

# Run tests (no hardware required — all PVS I/O is mocked)
pip3 install pytest
pytest test_sunpower_monitor.py -v

# Run a single test
pytest test_sunpower_monitor.py -v -k "test_ct_correction"

# On the Pi: manage the systemd service
sudo systemctl status sunpower
sudo systemctl restart sunpower
sudo journalctl -u sunpower -f
```

## Architecture

Single-file Flask app (`sunpower_monitor.py`) + Jinja template (`templates/dashboard.html`). There is no build step and no JS framework.

**Data flow:**
1. Flask route hits `fetch_all_data()` on every `/api/data` request
2. `fetch_all_data()` calls `varserver_get()` for four varserver endpoints: `inverter`, `meter`, `/sys/livedata`, `/sys/info`
3. `_group_by_device()` transforms the flat `{"/sys/devices/inverter/0/sn": "..."}` dict returned by the PVS into nested `{"0": {"sn": "..."}}` dicts
4. Per-panel daily kWh is computed by `record_reading()`, which writes `history.json` (the only persistent state)
5. The response JSON is returned directly to the browser; `dashboard.html` renders it client-side with vanilla JS

**`history.json` schema:**
```json
{
  "baselines": { "YYYY-MM-DD": { "SERIAL": <first_lifetime_kwh_seen_that_day> } },
  "last_seen":  { "YYYY-MM-DD": { "SERIAL": <most_recent_lifetime_kwh> } }
}
```
Daily production = `last_seen[D][serial] - baselines[D][serial]`. Grid meter entries use sentinel keys `__grid_import__` and `__grid_export__`. Baselines are set on the **first reading of the day** — if the Pi is down overnight and only comes back at noon, that noon lifetime value becomes the baseline, and any production before noon is permanently lost for that day.

**Access tier detection (`is_tailscale_direct()`):**
- `X-Forwarded-For` present → Tailscale Funnel (public) → `redact_for_public()` strips serials, MAC, host
- No `X-Forwarded-For` + IP in `100.64.0.0/10` or loopback → trusted (full data, per-panel history)

**CT clamp correction (`CT_CORRECTION`):**
When `home_kw < -0.1` the consumption meter CT is backwards. With correction enabled (default), `home_kw` is recalculated as `pv − |reported_home|` and `net_kw` is forced negative (export). Set `ct_correction: false` in `config.json` to disable.

## Configuration

`config.json` (gitignored) or environment variables:

| Key | Env var | Default | Notes |
|---|---|---|---|
| `pvs_host` | `PVS_HOST` | `sunpowerlocal` | IP or mDNS hostname of PVS6, no `https://` prefix |
| `pvs_password` | `PVS_PASSWORD` | — | **Last 5 chars** of PVS6 serial (case-sensitive) |
| `port` | `FLASK_RUN_PORT` | `5001` | |
| `ct_correction` | `CT_CORRECTION` | `true` | See above |

## Security

- **Auth:** HTTP Basic over HTTPS to the PVS6 (`ssm_owner:<last-5-of-serial>`). The session cookie is reused; re-auth fires automatically on 401/403.
- **Self-signed cert:** `urllib3` warnings suppressed; `requests.Session(verify=False)` throughout — expected, the PVS6 uses its own CA.
- **Rate limiting:** 60 req/min per IP enforced in `before_request` for all `/api/*` routes.
- **Data redaction:** `redact_for_public()` is called on all Funnel responses — serials, MAC, Wi-Fi password, and PVS host are masked. Wi-Fi password is also masked on the `/api/network` route for Funnel callers.
- **Network writes:** `write_var()` exists but no route currently calls it (firmware 2025.09+ made the varserver read-only anyway).

## Deployment (Pi)

- Service file: `/etc/systemd/system/sunpower.service` — runs `gunicorn --workers 2 --bind 0.0.0.0:5001`
- `history.json` lives in the working directory (same folder as `sunpower_monitor.py`). Back it up before migrating.
- Remote access via Tailscale VPN (`http://<pi-tailscale-ip>:5001`) or Tailscale Funnel for public/phone access.
- If the Pi loses power or reboots, the baseline for that day is reset to the lifetime value at restart — any production before that point is unrecoverable from `history.json` alone.

## Tests

63 tests; no PVS hardware needed — all `varserver_get` calls are patched with `unittest.mock`. Test helpers `_inverter_flat()` and `_meter_flat()` build the raw flat-dict format that the real PVS returns. `_varserver_side_effect()` wires them into a mock side-effect by matching the query-string prefix.
