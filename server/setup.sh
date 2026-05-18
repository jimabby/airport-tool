#!/usr/bin/env bash
# Shadowsocks-libev + v2ray-plugin server setup
# Tested on Ubuntu 20.04/22.04 and Debian 11/12
# Run as root: curl -sL <url> | bash
# Or: bash setup.sh

set -euo pipefail

### ── CONFIG (edit these before running) ──────────────────────────────────── ###
SS_PORT="${SS_PORT:-8388}"
SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 16)}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
DOMAIN="${DOMAIN:-}"          # Optional: your domain for TLS mode. Leave empty for WebSocket-only.
V2RAY_PLUGIN_MODE="${V2RAY_PLUGIN_MODE:-websocket}"   # websocket or tls (requires DOMAIN)
### ─────────────────────────────────────────────────────────────────────────── ###

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Please run as root (sudo bash setup.sh)"

ARCH=$(uname -m)
OS_ID=$(. /etc/os-release && echo "$ID")
info "Detected OS: $OS_ID | Arch: $ARCH"

# ── 1. Install dependencies ────────────────────────────────────────────────── #
info "Updating package lists..."
apt-get update -qq

info "Installing shadowsocks-libev..."
apt-get install -y -qq shadowsocks-libev

# ── 2. Install v2ray-plugin ───────────────────────────────────────────────── #
info "Installing v2ray-plugin..."
V2RAY_VER="1.3.2"
case "$ARCH" in
  x86_64)  ARCH_TAG="amd64" ;;
  aarch64) ARCH_TAG="arm64" ;;
  armv7*)  ARCH_TAG="armv7" ;;
  *)       error "Unsupported architecture: $ARCH" ;;
esac

V2RAY_URL="https://github.com/teddysun/v2ray-plugin/releases/download/v${V2RAY_VER}/v2ray-plugin-linux-${ARCH_TAG}-v${V2RAY_VER}.tar.gz"
TMP_DIR=$(mktemp -d)
curl -sL "$V2RAY_URL" -o "$TMP_DIR/v2ray-plugin.tar.gz"
tar -xzf "$TMP_DIR/v2ray-plugin.tar.gz" -C "$TMP_DIR"
install -m 755 "$TMP_DIR/v2ray-plugin-linux-${ARCH_TAG}" /usr/local/bin/v2ray-plugin
rm -rf "$TMP_DIR"
info "v2ray-plugin installed: $(v2ray-plugin -version 2>&1 | head -1)"

# ── 3. Write Shadowsocks config ───────────────────────────────────────────── #
info "Writing Shadowsocks config..."

if [[ "$V2RAY_PLUGIN_MODE" == "tls" && -n "$DOMAIN" ]]; then
  PLUGIN_OPTS="server;tls;host=${DOMAIN};path=/ws"
  warn "TLS mode: make sure your domain points to this server and port 443 is open."
  warn "You may also want to set up certbot for a real TLS cert."
else
  PLUGIN_OPTS="server"
  warn "WebSocket mode (no TLS). Suitable for most use cases behind a CDN or with obfuscation."
fi

mkdir -p /etc/shadowsocks-libev
cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "plugin": "v2ray-plugin",
    "plugin_opts": "${PLUGIN_OPTS}",
    "timeout": 300,
    "fast_open": false,
    "mode": "tcp_only"
}
EOF

# ── 4. Configure systemd service ──────────────────────────────────────────── #
info "Configuring systemd service..."
systemctl stop shadowsocks-libev 2>/dev/null || true

cat > /etc/systemd/system/shadowsocks-libev.service <<'EOF'
[Unit]
Description=Shadowsocks-libev with v2ray-plugin
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/bin/ss-server -c /etc/shadowsocks-libev/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shadowsocks-libev
systemctl start shadowsocks-libev

# ── 5. Configure firewall ─────────────────────────────────────────────────── #
info "Configuring firewall (ufw)..."
if command -v ufw &>/dev/null; then
  ufw allow "$SS_PORT"/tcp
  ufw allow 22/tcp  # keep SSH open!
  ufw --force enable
else
  warn "ufw not found. Make sure port $SS_PORT/tcp is open in your provider's firewall panel."
fi

# ── 6. Output connection info ─────────────────────────────────────────────── #
SERVER_IP=$(curl -s4 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Shadowsocks setup complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Server IP  : $SERVER_IP"
echo "  Port       : $SS_PORT"
echo "  Password   : $SS_PASSWORD"
echo "  Method     : $SS_METHOD"
echo "  Plugin     : v2ray-plugin"
echo "  Plugin opts: $PLUGIN_OPTS"
echo ""

# Build SS URI (base64 encoded)
SS_USERINFO=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0)
SS_URI="ss://${SS_USERINFO}@${SERVER_IP}:${SS_PORT}?plugin=v2ray-plugin%3B${PLUGIN_OPTS// /+}"
echo "  SS URI (import into clients):"
echo "  $SS_URI"
echo ""

# Save config summary for use by the web UI config-gen tool
mkdir -p /etc/airport-tool
cat > /etc/airport-tool/server.env <<ENVEOF
SS_SERVER=${SERVER_IP}
SS_PORT=${SS_PORT}
SS_PASSWORD=${SS_PASSWORD}
SS_METHOD=${SS_METHOD}
SS_PLUGIN=v2ray-plugin
SS_PLUGIN_OPTS=${PLUGIN_OPTS}
SS_URI=${SS_URI}
ENVEOF
chmod 600 /etc/airport-tool/server.env

echo -e "${GREEN}  Config saved to /etc/airport-tool/server.env${NC}"
echo -e "${YELLOW}  Run 'systemctl status shadowsocks-libev' to verify.${NC}"
echo ""
