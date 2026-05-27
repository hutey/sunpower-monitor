#!/usr/bin/env bash
# deploy.sh — Deploy SunPower Monitor to the Pi and reload the service
#
# Usage:
#   ./deploy.sh              # deploy + reload (zero-downtime SIGHUP)
#   ./deploy.sh --dry-run    # show what would be deployed, no transfer
#   ./deploy.sh --status     # check service + API status only
#   ./deploy.sh --restart    # full stop+start instead of graceful reload
#   ./deploy.sh --setup-sudo # install passwordless sudoers rule (interactive)
#
# Reload strategy (default):
#   Sends SIGHUP to the gunicorn master — workers restart gracefully,
#   picking up new code. No sudo required; gsingh owns the process.
#
# Restart strategy (--restart or when pidfile is missing):
#   Tries systemd if sudoers rule is in place, else starts gunicorn
#   directly with a pidfile at /tmp/sunpower.pid.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CFG="$SCRIPT_DIR/config.json"

# ── Load config ───────────────────────────────────────────────────────────────
if [[ ! -f "$CFG" ]]; then
  echo "✗  config.json not found at $CFG" >&2; exit 1
fi

PI_USER=$(python3 -c "import json; c=json.load(open('$CFG')); print(c.get('pi_user','pi'))")
PI_HOST=$(python3 -c "import json; c=json.load(open('$CFG')); print(c.get('pi_host','pisunpower.local'))")
PI_IP=$(python3 -c "
import socket, json
c = json.load(open('$CFG'))
# Use explicit pi_ip if set, otherwise resolve the hostname
if c.get('pi_ip'):
    print(c['pi_ip'])
    exit()
try:
    print(socket.gethostbyname(c.get('pi_host','pisunpower.local')))
except Exception:
    print(c.get('pi_host','pisunpower.local'))
")
REMOTE_DIR="/home/${PI_USER}/sunpower"
VENV="/home/${PI_USER}/pisunpower-env"
PID_FILE="/tmp/sunpower.pid"
LOG_FILE="/tmp/sunpower.log"

SSH_OPTS="-4 -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10"

DEPLOY_FILES=(
  "sunpower_monitor.py"
  "templates/dashboard.html"
  "requirements.txt"
)

DRY_RUN=false
STATUS_ONLY=false
FORCE_RESTART=false
SETUP_SUDO=false
for arg in "$@"; do
  case $arg in
    --dry-run)      DRY_RUN=true ;;
    --status)       STATUS_ONLY=true ;;
    --restart)      FORCE_RESTART=true ;;
    --setup-sudo)   SETUP_SUDO=true ;;
  esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()   { echo "  ✅  $*"; }
err()  { echo "  ✗   $*" >&2; }
info() { echo "  ℹ   $*"; }
warn() { echo "  ⚠️   $*"; }
step() { echo; echo "── $* ──────────────────────────────────────"; }

pi_ssh() { ssh $SSH_OPTS "${PI_USER}@${PI_IP}" "$@"; }
pi_scp() { scp $SSH_OPTS "$@"; }

# ── Connectivity check ────────────────────────────────────────────────────────
assert_ssh() {
  if ! pi_ssh "echo ok" &>/dev/null; then
    err "Cannot SSH to ${PI_USER}@${PI_IP}"; exit 1
  fi
}

# ── API health check ──────────────────────────────────────────────────────────
check_api() {
  local result
  result=$(pi_ssh "curl -s --max-time 10 http://localhost:5001/api/data | python3 -c \"
import json,sys
d=json.load(sys.stdin)
print(d.get('ok'), d.get('summary',{}).get('total_kw','—'), d.get('error',''))
\"" 2>/dev/null) || true
  read -r API_OK KW API_ERR <<< "$result"
  if [[ "$API_OK" == "True" ]]; then
    ok "API healthy — ${KW} kW solar now"
    return 0
  else
    err "API error: ${API_ERR:-no response}"
    return 1
  fi
}

# ── Setup sudoers ─────────────────────────────────────────────────────────────
if $SETUP_SUDO; then
  step "Setting up passwordless sudoers rule"
  assert_ssh
  # Check if already in place
  if pi_ssh "sudo -n systemctl status sunpower" &>/dev/null; then
    ok "Sudoers rule already configured"
    exit 0
  fi
  info "You will be prompted for your sudo password on the Pi once:"
  ssh $SSH_OPTS -t "${PI_USER}@${PI_IP}" \
    "echo '${PI_USER} ALL=(ALL) NOPASSWD: /bin/systemctl start sunpower, /bin/systemctl stop sunpower, /bin/systemctl restart sunpower, /bin/systemctl status sunpower' | sudo tee /etc/sudoers.d/sunpower && sudo chmod 440 /etc/sudoers.d/sunpower"
  ok "Sudoers rule installed — future deploys use systemd restart"
  exit 0
fi

# ── Status only ───────────────────────────────────────────────────────────────
if $STATUS_ONLY; then
  assert_ssh
  step "Service / process"
  pi_ssh "
    ACTIVE=\$(systemctl is-active sunpower 2>/dev/null || echo inactive)
    echo \"  systemd: \$ACTIVE\"
    PID=\$(cat $PID_FILE 2>/dev/null || echo '')
    if [ -n \"\$PID\" ] && kill -0 \$PID 2>/dev/null; then
      echo \"  gunicorn master PID: \$PID (running)\"
    else
      echo \"  gunicorn master PID: not found\"
    fi
    echo \"  uptime: \$(uptime -p 2>/dev/null)\"
  "
  step "API"
  check_api || true
  step "Last 10 log lines"
  pi_ssh "tail -10 $LOG_FILE 2>/dev/null || journalctl -u sunpower -n 10 --no-pager 2>/dev/null || echo '  (no logs found)'"
  exit 0
fi

# ── Pre-flight ────────────────────────────────────────────────────────────────
step "Pre-flight  →  ${PI_USER}@${PI_IP}"
assert_ssh
ok "SSH connection OK"

# Detect how to reload/restart
HAS_SUDO_SYSTEMCTL=false
# systemctl status returns exit 3 when service is inactive — use 'is-enabled' instead
if pi_ssh "sudo -n systemctl is-enabled sunpower" &>/dev/null; then
  HAS_SUDO_SYSTEMCTL=true
  ok "Passwordless systemctl available"
else
  info "No passwordless sudo — will use SIGHUP reload (run './deploy.sh --setup-sudo' once to enable systemctl)"
fi

# ── Show deploy manifest ──────────────────────────────────────────────────────
step "Files to deploy → ${REMOTE_DIR}"
for f in "${DEPLOY_FILES[@]}"; do
  if [[ -f "$SCRIPT_DIR/$f" ]]; then
    size=$(du -sh "$SCRIPT_DIR/$f" | cut -f1)
    echo "  📄  $f  (${size})"
  else
    warn "Not found: $f — skipping"
  fi
done

if $DRY_RUN; then
  echo; info "Dry run — nothing transferred."; exit 0
fi

# ── Deploy files ──────────────────────────────────────────────────────────────
step "Deploying"
for f in "${DEPLOY_FILES[@]}"; do
  src="$SCRIPT_DIR/$f"
  [[ -f "$src" ]] || continue
  subdir=$(dirname "$f")
  [[ "$subdir" != "." ]] && pi_ssh "mkdir -p ${REMOTE_DIR}/${subdir}"
  pi_scp "$src" "${PI_USER}@${PI_IP}:${REMOTE_DIR}/${f}"
  ok "$f"
done

# ── Reload / restart ──────────────────────────────────────────────────────────
step "Reloading"

if $HAS_SUDO_SYSTEMCTL; then
  # Preferred: systemd manages the full lifecycle
  pi_ssh "sudo systemctl restart sunpower"
  ok "systemd restart complete"
else
  # No sudo: use gunicorn signals directly (gsingh owns the process)
  GUNICORN_RUNNING=$(pi_ssh "
    PID=\$(cat $PID_FILE 2>/dev/null || echo '')
    if [ -n \"\$PID\" ] && kill -0 \$PID 2>/dev/null; then echo yes; else echo no; fi
  ")

  if [[ "$GUNICORN_RUNNING" == "yes" ]] && ! $FORCE_RESTART; then
    # Zero-downtime: SIGHUP tells gunicorn master to gracefully restart workers
    pi_ssh "kill -HUP \$(cat $PID_FILE)"
    ok "SIGHUP sent — workers reloading gracefully"
  else
    # Full start (first deploy or --restart) — write a helper script to the Pi
    # via mktemp to avoid TOCTOU races on /tmp, then run and clean up
    info "Starting gunicorn fresh..."
    pi_ssh "
      _TMP=\$(mktemp /tmp/_sp_start_XXXXXX.sh)
      cat > \"\$_TMP\" << 'EOF'
#!/bin/bash
pkill -f 'gunicorn.*sunpower' 2>/dev/null
sleep 1
rm -f $PID_FILE
cd $REMOTE_DIR
nohup $VENV/bin/gunicorn \
  --workers 2 --bind 0.0.0.0:5001 --timeout 60 \
  --pid $PID_FILE \
  sunpower_monitor:app \
  >> $LOG_FILE 2>&1 &
EOF
      chmod 700 \"\$_TMP\"
      bash \"\$_TMP\"
      rm -f \"\$_TMP\"
    "
    sleep 4
    MASTER_PID=$(pi_ssh "cat $PID_FILE 2>/dev/null || echo 'unknown'")
    ok "Started — master PID ${MASTER_PID}"
  fi
fi

# ── Verify ────────────────────────────────────────────────────────────────────
step "Verifying"
sleep 3
check_api

echo
echo "✅  Deploy complete."
