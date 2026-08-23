#!/usr/bin/env bash
# Install the dashboard as a systemd service, filled in for this machine.
#
# The health monitor only runs while the dashboard process does. Started from a
# terminal it dies with the terminal, which means the one feature whose whole
# job is to notice an outage while you are not looking stops the moment you stop
# looking. This wires it into systemd instead.
#
#   sudo bash web-ui/install-service.sh              # install and start
#   sudo bash web-ui/install-service.sh --uninstall  # remove it again
#
# Everything it needs is derived from where this script lives and who owns the
# checkout, so there is nothing to edit first.

set -euo pipefail

UNIT_NAME=airport-ui
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}.service"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${HERE}/${UNIT_NAME}.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root (sudo bash install-service.sh)"
command -v systemctl >/dev/null 2>&1 || error "systemd is not available on this machine."

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
  info "Removed ${UNIT_NAME}. servers.json and your profiles were left alone."
  exit 0
fi

[[ -f "$TEMPLATE" ]] || error "Cannot find ${TEMPLATE}"
[[ -f "${HERE}/server.js" ]] || error "Cannot find ${HERE}/server.js — run this from inside the repo."
[[ -d "${HERE}/node_modules" ]] || error "Dependencies are missing. Run 'npm install' in ${HERE} first."

NODE_BIN="$(command -v node)" || error "node is not on PATH."

# Run as whoever owns the checkout, not as root: this process reads and rewrites
# a file full of proxy credentials and needs no privilege beyond that file.
OWNER="$(stat -c '%U' "${HERE}/server.js")"
GROUP="$(stat -c '%G' "${HERE}/server.js")"
if [[ "$OWNER" == "root" ]]; then
  warn "This checkout is owned by root, so the service will run as root too."
  warn "Owning it as a normal user (chown -R youruser ${HERE}/..) is safer."
fi

# servers.json lives beside the CLI generator, and the service has to be able to
# write it — ProtectSystem=strict makes everything else read-only.
STATE_DIR="$(cd "${HERE}/../config-gen" && pwd)"

sed -e "s#REPLACE_USER#${OWNER}#" \
    -e "s#REPLACE_GROUP#${GROUP}#" \
    -e "s#REPLACE_DIR#${HERE}#" \
    -e "s#REPLACE_NODE#${NODE_BIN}#" \
    -e "s#REPLACE_STATE#${STATE_DIR}#" \
    "$TEMPLATE" > "$UNIT_PATH"
chmod 644 "$UNIT_PATH"

systemctl daemon-reload
systemctl enable "$UNIT_NAME" >/dev/null
systemctl restart "$UNIT_NAME"
sleep 2

if systemctl is-active --quiet "$UNIT_NAME"; then
  info "${UNIT_NAME} is running as ${OWNER} from ${HERE}."
  info "Dashboard URL (token included) is in the log:"
  echo ""
  journalctl -u "$UNIT_NAME" -n 15 --no-pager 2>/dev/null || true
  echo ""
  info "Follow it with:  journalctl -u ${UNIT_NAME} -f"
  warn "Turn the health monitor on in the dashboard — it is off by default, and"
  warn "it is the reason for running this as a service at all."
else
  warn "${UNIT_NAME} failed to start. Recent log:"
  journalctl -u "$UNIT_NAME" -n 20 --no-pager 2>/dev/null || true
  error "Fix the above, then: systemctl restart ${UNIT_NAME}"
fi
