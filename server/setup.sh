#!/usr/bin/env bash
# Airport server setup — Shadowsocks (v2ray-plugin) or VLESS + Reality.
# Tested on Ubuntu 20.04/22.04/24.04 and Debian 11/12.
# Run as root:  sudo bash setup.sh
#   or:  PROTOCOL=reality bash <(curl -sL <url>)
#
# Env knobs:
#   PROTOCOL          shadowsocks | reality        (default: shadowsocks)
#   SS_PORT           Shadowsocks port             (default: 8388)
#   SS_PASSWORD       Shadowsocks password         (default: random)
#   SS_METHOD         Shadowsocks cipher           (default: chacha20-ietf-poly1305)
#   DOMAIN            Domain for real TLS (certbot) — Shadowsocks TLS mode
#   V2RAY_PLUGIN_MODE websocket | tls              (default: websocket)
#   REALITY_PORT      VLESS/Reality port           (default: 443)
#   REALITY_SNI       Borrowed TLS domain          (default: www.microsoft.com)

set -euo pipefail

### ── Config ────────────────────────────────────────────────────────────────── ###
PROTOCOL="${PROTOCOL:-shadowsocks}"

SS_PORT="${SS_PORT:-8388}"
SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 16)}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
DOMAIN="${DOMAIN:-}"
V2RAY_PLUGIN_MODE="${V2RAY_PLUGIN_MODE:-websocket}"

REALITY_PORT="${REALITY_PORT:-443}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
### ─────────────────────────────────────────────────────────────────────────── ###

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# Percent-encode a string like JS encodeURIComponent (keeps A-Za-z0-9-_.~), so
# the printed URI matches what config-gen/lib/configs.js emits.
urlencode() {
  local s="$1" i c out=""
  for (( i=0; i<${#s}; i++ )); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) out+=$(printf '%%%02X' "'$c") ;;
    esac
  done
  printf '%s' "$out"
}

[[ $EUID -ne 0 ]] && error "Please run as root (sudo bash setup.sh)"

ARCH=$(uname -m)
OS_ID=$(. /etc/os-release && echo "$ID")
info "OS: $OS_ID | Arch: $ARCH | Protocol: $PROTOCOL"

SERVER_IP=$(curl -s4 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')
mkdir -p /etc/airport-tool

# ── Firewall helper ─────────────────────────────────────────────────────────── #
open_port() {
  local port="$1" proto="${2:-tcp}"
  if command -v ufw &>/dev/null; then
    ufw allow "$port"/"$proto" >/dev/null
  fi
}

#############################################################################
# Shadowsocks + v2ray-plugin
#############################################################################
setup_shadowsocks() {
  info "Installing shadowsocks-libev..."
  apt-get update -qq
  apt-get install -y -qq shadowsocks-libev

  info "Installing v2ray-plugin..."
  local V2RAY_VER="1.3.2" ARCH_TAG
  case "$ARCH" in
    x86_64)  ARCH_TAG="amd64" ;;
    aarch64) ARCH_TAG="arm64" ;;
    armv7*)  ARCH_TAG="armv7" ;;
    *)       error "Unsupported architecture: $ARCH" ;;
  esac
  local url="https://github.com/teddysun/v2ray-plugin/releases/download/v${V2RAY_VER}/v2ray-plugin-linux-${ARCH_TAG}-v${V2RAY_VER}.tar.gz"
  local tmp; tmp=$(mktemp -d)
  curl -sL "$url" -o "$tmp/v2ray-plugin.tar.gz"
  tar -xzf "$tmp/v2ray-plugin.tar.gz" -C "$tmp"
  install -m 755 "$tmp/v2ray-plugin-linux-${ARCH_TAG}" /usr/local/bin/v2ray-plugin
  rm -rf "$tmp"
  info "v2ray-plugin: $(v2ray-plugin -version 2>&1 | head -1)"

  # Server-side and client-side plugin opts are built separately: server opts
  # carry `server`/`cert`/`key`, which must never appear in a client URI.
  local SERVER_OPTS CLIENT_OPTS
  if [[ "$V2RAY_PLUGIN_MODE" == "tls" && -n "$DOMAIN" ]]; then
    info "TLS mode: obtaining a Let's Encrypt certificate for $DOMAIN..."
    apt-get install -y -qq certbot
    open_port 80; open_port 443
    certbot certonly --standalone --non-interactive --agree-tos \
      --register-unsafely-without-email -d "$DOMAIN" || error "certbot failed — is $DOMAIN pointed at $SERVER_IP and port 80 free?"

    # ss-server runs as 'nobody' and can't read /etc/letsencrypt (root 0600),
    # so copy the cert into a readable spot and keep it fresh on renewal.
    install_cert_copy "$DOMAIN"
    SERVER_OPTS="server;tls;host=${DOMAIN};cert=/etc/shadowsocks-libev/cert.pem;key=/etc/shadowsocks-libev/key.pem;path=/ws"
    CLIENT_OPTS="tls;host=${DOMAIN};path=/ws"
    SS_HOST="$DOMAIN"
  else
    SERVER_OPTS="server"
    CLIENT_OPTS=""
    SS_HOST="$SERVER_IP"
    warn "WebSocket mode (no TLS). Fine behind a CDN or for basic obfuscation."
  fi

  info "Writing Shadowsocks config..."
  mkdir -p /etc/shadowsocks-libev
  cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "0.0.0.0",
    "server_port": ${SS_PORT},
    "password": "${SS_PASSWORD}",
    "method": "${SS_METHOD}",
    "plugin": "v2ray-plugin",
    "plugin_opts": "${SERVER_OPTS}",
    "timeout": 300,
    "fast_open": false,
    "mode": "tcp_only"
}
EOF

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
  systemctl restart shadowsocks-libev

  open_port "$SS_PORT"; open_port 22
  command -v ufw &>/dev/null && ufw --force enable >/dev/null || \
    warn "ufw not found — open $SS_PORT/tcp in your provider's firewall."

  # Build client URI (strip server-only opts; URL-encode the separators).
  local userinfo plugin_param encoded
  # SIP002 userinfo: web-safe base64 (base64url, no padding) to match config-gen.
  userinfo=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0 | tr '+/' '-_' | tr -d '=')
  if [[ -n "$CLIENT_OPTS" ]]; then plugin_param="v2ray-plugin;${CLIENT_OPTS}"; else plugin_param="v2ray-plugin"; fi
  encoded=$(urlencode "$plugin_param")
  SS_URI="ss://${userinfo}@${SS_HOST}:${SS_PORT}?plugin=${encoded}#Airport"

  print_result "Shadowsocks" \
    "Server=${SS_HOST}" "Port=${SS_PORT}" "Password=${SS_PASSWORD}" \
    "Method=${SS_METHOD}" "Plugin opts=${SERVER_OPTS}"
  echo "  URI: $SS_URI"

  cat > /etc/airport-tool/server.env <<ENVEOF
PROTOCOL=shadowsocks
SS_SERVER=${SS_HOST}
SS_PORT=${SS_PORT}
SS_PASSWORD=${SS_PASSWORD}
SS_METHOD=${SS_METHOD}
SS_PLUGIN=v2ray-plugin
SS_PLUGIN_OPTS=${SERVER_OPTS}
SS_URI=${SS_URI}
ENVEOF
  chmod 600 /etc/airport-tool/server.env

  # Emit a ready-to-use profile for servers.json / the web UI.
  cat > /etc/airport-tool/profile.json <<PJEOF
{
  "protocol": "shadowsocks",
  "server": "${SS_HOST}",
  "port": ${SS_PORT},
  "password": "${SS_PASSWORD}",
  "method": "${SS_METHOD}",
  "plugin": "v2ray-plugin",
  "plugin_opts": "$( [[ -n "$CLIENT_OPTS" ]] && echo "server;${CLIENT_OPTS}" || echo "server" )",
  "remarks": "Airport SS"
}
PJEOF
}

# Copy the live cert into a nobody-readable location and register a renewal hook.
install_cert_copy() {
  local domain="$1"
  cp "/etc/letsencrypt/live/${domain}/fullchain.pem" /etc/shadowsocks-libev/cert.pem
  cp "/etc/letsencrypt/live/${domain}/privkey.pem"   /etc/shadowsocks-libev/key.pem
  chown nobody:nogroup /etc/shadowsocks-libev/cert.pem /etc/shadowsocks-libev/key.pem 2>/dev/null || \
    chown nobody:nobody /etc/shadowsocks-libev/cert.pem /etc/shadowsocks-libev/key.pem
  chmod 600 /etc/shadowsocks-libev/cert.pem /etc/shadowsocks-libev/key.pem

  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/airport-ss.sh <<HOOK
#!/usr/bin/env bash
cp "/etc/letsencrypt/live/${domain}/fullchain.pem" /etc/shadowsocks-libev/cert.pem
cp "/etc/letsencrypt/live/${domain}/privkey.pem"   /etc/shadowsocks-libev/key.pem
chown nobody:nogroup /etc/shadowsocks-libev/cert.pem /etc/shadowsocks-libev/key.pem 2>/dev/null || true
chmod 600 /etc/shadowsocks-libev/cert.pem /etc/shadowsocks-libev/key.pem
systemctl restart shadowsocks-libev
HOOK
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/airport-ss.sh
}

#############################################################################
# VLESS + Reality (Xray-core)
#############################################################################
setup_reality() {
  info "Installing Xray-core..."
  apt-get update -qq
  apt-get install -y -qq curl openssl
  bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >/dev/null

  info "Generating Reality keys, UUID and short ID..."
  local keypair priv pub uuid sid
  keypair=$(xray x25519)
  priv=$(echo "$keypair" | awk '/Private key:/ {print $3}')
  pub=$(echo  "$keypair" | awk '/Public key:/ {print $3}')
  uuid=$(xray uuid)
  sid=$(openssl rand -hex 8)

  info "Writing Xray config (SNI: ${REALITY_SNI})..."
  mkdir -p /usr/local/etc/xray
  cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "port": ${REALITY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${uuid}", "flow": "xtls-rprx-vision" } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_SNI}:443",
          "xver": 0,
          "serverNames": [ "${REALITY_SNI}" ],
          "privateKey": "${priv}",
          "shortIds": [ "${sid}" ]
        }
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
EOF

  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray

  open_port "$REALITY_PORT"; open_port 22
  command -v ufw &>/dev/null && ufw --force enable >/dev/null || \
    warn "ufw not found — open ${REALITY_PORT}/tcp in your provider's firewall."

  # Build the vless:// URI.
  REALITY_URI="vless://${uuid}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${pub}&sid=${sid}&type=tcp#Airport%20Reality"

  print_result "VLESS + Reality" \
    "Server=${SERVER_IP}" "Port=${REALITY_PORT}" "UUID=${uuid}" \
    "PublicKey=${pub}" "ShortID=${sid}" "SNI=${REALITY_SNI}"
  echo "  URI: $REALITY_URI"

  cat > /etc/airport-tool/server.env <<ENVEOF
PROTOCOL=reality
REALITY_SERVER=${SERVER_IP}
REALITY_PORT=${REALITY_PORT}
REALITY_UUID=${uuid}
REALITY_PUBLIC_KEY=${pub}
REALITY_SHORT_ID=${sid}
REALITY_SNI=${REALITY_SNI}
REALITY_URI=${REALITY_URI}
ENVEOF
  chmod 600 /etc/airport-tool/server.env

  cat > /etc/airport-tool/profile.json <<PJEOF
{
  "protocol": "vless-reality",
  "server": "${SERVER_IP}",
  "port": ${REALITY_PORT},
  "uuid": "${uuid}",
  "publicKey": "${pub}",
  "shortId": "${sid}",
  "sni": "${REALITY_SNI}",
  "flow": "xtls-rprx-vision",
  "fingerprint": "chrome",
  "remarks": "Airport Reality"
}
PJEOF
}

# ── Pretty result block ─────────────────────────────────────────────────────── #
print_result() {
  local title="$1"; shift
  echo ""
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "${GREEN}  ${title} setup complete!${NC}"
  echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
  for kv in "$@"; do echo "  ${kv%%=*}: ${kv#*=}"; done
  echo ""
}

# ── Dispatch ────────────────────────────────────────────────────────────────── #
case "$PROTOCOL" in
  shadowsocks|ss) setup_shadowsocks ;;
  reality|vless)  setup_reality ;;
  *)              error "Unknown PROTOCOL: $PROTOCOL (use 'shadowsocks' or 'reality')" ;;
esac

echo -e "${GREEN}  Config + client profile saved to /etc/airport-tool/${NC}"
echo -e "${YELLOW}  A ready-to-import profile is at /etc/airport-tool/profile.json${NC}"
echo -e "${YELLOW}  Copy it into config-gen/servers.json to generate client configs.${NC}"
echo ""
