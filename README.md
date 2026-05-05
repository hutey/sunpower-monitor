# SunPower Local Monitor

A self-hosted real-time solar dashboard for SunPower / SunStrong systems. Reads live data directly from your PVS6 over the local network using the authenticated varserver FCGI API — no cloud, no subscription.

Built with Python · Flask · Tailscale · Raspberry Pi

---

## Features

- Live solar production, home consumption, and grid flow (import/export)
- Energy flow diagram: Solar → Home → Grid
- Per-panel microinverter detail: watts, daily kWh, lifetime kWh, DC voltage, AC voltage, current, temperature, frequency
- Daily production history with per-panel breakdown and grid energy accounting
- Network tab: WiFi SSID, active interface, cellular/broadband status
- Diagnostics tab: full meter readings (power, current, voltage, power factor, CT scale), livedata variables, and automatic CT clamp issue detection
- CT clamp correction: if the consumption meter CT is oriented backwards, the dashboard automatically corrects the negative home load reading and flags it
- Tiered access: full data over Tailscale VPN, read-only with redacted identifiers via Tailscale Funnel (public)
- Rate limiting (60 req/min per IP) and XSS protection
- Auto-refreshes every 30 seconds

---

## Requirements

- SunPower PVS6 (firmware build 61840+, i.e. firmware 2025.09+)
- Python 3.9+
- A Raspberry Pi (or any always-on Linux machine) on your home network
- A free [Tailscale](https://tailscale.com) account for remote access

---

## Quick Start (Mac / local)

```bash
git clone https://github.com/hutey/sunpower-monitor.git
cd sunpower-monitor
pip3 install -r requirements.txt
cp config.example.json config.json
```

Edit `config.json` with your PVS6 details:

```json
{
  "pvs_host": "192.168.1.x",
  "pvs_password": "XXXXX",
  "port": 5001
}
```

- `pvs_host` — local IP of your PVS6 (find it in your router's device list)
- `pvs_password` — **last 5 characters** of the PVS6 serial number (case-sensitive)

Run it:

```bash
python3 sunpower_monitor.py
```

Open `http://localhost:5001` in your browser.

---

## Raspberry Pi Setup (always-on)

### 1. Flash the Pi

Use [Raspberry Pi Imager](https://www.raspberrypi.com/software/) to flash **Raspberry Pi OS Lite (64-bit)**. In the settings (gear icon), configure:
- Hostname (e.g. `sunpower`)
- SSH enabled with username/password
- Your Wi-Fi credentials

### 2. Copy files and install dependencies

```bash
scp sunpower_monitor.py config.json requirements.txt YOUR_USER@sunpower.local:~/
ssh YOUR_USER@sunpower.local

python3 -m venv ~/sunpower-env
~/sunpower-env/bin/pip install -r requirements.txt
```

### 3. Set up as a system service

```bash
sudo nano /etc/systemd/system/sunpower.service
```

```ini
[Unit]
Description=SunPower Monitor
After=network-online.target
Wants=network-online.target

[Service]
User=YOUR_USER
WorkingDirectory=/home/YOUR_USER
ExecStart=/home/YOUR_USER/sunpower-env/bin/gunicorn --workers 2 --bind 0.0.0.0:5001 --timeout 60 sunpower_monitor:app
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable sunpower
sudo systemctl start sunpower
```

### 4. Remote access via Tailscale

Install Tailscale on the Pi:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Install the Tailscale app on your phone, sign in with the same account. Access the dashboard at `http://<pi-tailscale-ip>:5001` from anywhere.

**Add to iPhone home screen:** Safari → Share → Add to Home Screen.

---

## Access Tiers

| Feature | Local / Tailscale VPN | Tailscale Funnel (public) |
|---|---|---|
| Live dashboard | ✅ Full | ✅ Full |
| Panel serials | ✅ Full | Redacted (last 4 chars) |
| MAC address | ✅ Full | Redacted |
| Wi-Fi password | ✅ Full | Hidden |
| Per-panel history | ✅ Full | Daily totals only |
| Meter serials | ✅ Full | Redacted |
| PVS host | ✅ Full | Hidden |

Access is detected automatically: direct Tailscale VPN connections and local loopback are trusted; Tailscale Funnel connections (which inject an `X-Forwarded-For` header) are treated as public.

---

## API

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard (HTML) |
| `GET /api/data` | Live solar data: summary, panels, supervisor, diagnostics |
| `GET /api/history` | Daily production history |
| `GET /api/network` | Network and connectivity status |

All `/api/*` routes are rate-limited to 60 requests per minute per IP.

---

## Notes

- The PVS6 serial number is on the label on the unit. The password is the **last 5 characters** — e.g. if the serial ends in `XXXXX`, the password is `XXXXX`.
- `history.json` is created automatically and stores daily production baselines per panel and grid meter. Back it up if you migrate to a new device.
- Network settings shown in the Network tab are read-only on firmware 2025.09+. To change WiFi, use the SunStrong mobile app (Bluetooth commissioning) or the PVS hotspot setup page.

---

## Credits

Built with the help of [Claude](https://claude.ai).  
Based on [SunStrong's LocalAPI spec](https://github.com/SunStrong-Management/pypvs/blob/main/doc/LocalAPI.md).
