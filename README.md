# SunPower Local Monitor

A self-hosted real-time solar dashboard for SunPower / SunStrong systems. Reads live data directly from your PVS6 over the local network — no cloud, no subscription.

Built with Python · Flask · Tailscale · Raspberry Pi

---

## Features

- Live solar production, home consumption, and grid flow
- Per-panel detail with daily and lifetime kWh
- Daily production history
- CT clamp correction for flipped consumption meter wiring
- Tiered access: full data over Tailscale VPN, read-only with redacted identifiers via Tailscale Funnel
- Rate limiting and XSS protection

---

## Requirements

- SunPower PVS6 (firmware build 61840+, firmware 2025.09+)
- Python 3.9+
- A Raspberry Pi (or any always-on Linux machine) on your home network
- A free [Tailscale](https://tailscale.com) account for remote access

---

## Quick Start (Mac / local)

```bash
git clone https://github.com/YOUR_USERNAME/sunpower-monitor.git
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
scp sunpower_monitor.py config.json YOUR_USER@sunpower.local:~/
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

| Feature | Tailscale VPN | Tailscale Funnel (public) |
|---|---|---|
| Live dashboard | ✅ Full | ✅ Full |
| Panel serials | ✅ Full | Redacted |
| MAC address | ✅ Full | Redacted |
| Wi-Fi password | ✅ Full | Redacted |
| Per-panel history | ✅ Full | Daily totals only |

---

## Notes

- The PVS6 serial number is on the label on the unit. The password is the **last 5 characters** — e.g. if the serial ends in `W2208`, the password is `W2208`.
- CT clamp correction: if your consumption meter CT clamp is oriented backwards, the dashboard will automatically correct the negative home load reading.
- `history.json` is created automatically and stores daily production baselines. Back it up if you migrate to a new device.

---

## Credits

Built with the help of [Claude](https://claude.ai).  
Based on [SunStrong's LocalAPI spec](https://github.com/SunStrong-Management/pypvs/blob/main/doc/LocalAPI.md).
