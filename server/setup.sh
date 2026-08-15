#!/usr/bin/env bash
# Airport server setup — Shadowsocks (v2ray-plugin), VLESS + Reality, or Hysteria2.
# Tested on Ubuntu 20.04/22.04/24.04 and Debian 11/12.
#
# Run as root:  sudo bash setup.sh
#   or:  PROTOCOL=reality bash <(curl -sL <url>)
#
# Env knobs:
#   PROTOCOL          shadowsocks | reality | hysteria2   (default: shadowsocks)
#   FORCE             1 = regenerate keys/passwords even if a setup already exists
#   NO_BBR            1 = skip the BBR / network tuning step
#
#   SS_PORT           Shadowsocks port             (default: 8388)
#   SS_PASSWORD       Shadowsocks password         (default: random)
#   SS_METHOD         Shadowsocks cipher           (default: chacha20-ietf-poly1305)
#   DOMAIN            Domain for real TLS — Shadowsocks TLS mode / Hysteria2 ACME
#   V2RAY_PLUGIN_MODE websocket | tls              (default: websocket)
#
#   REALITY_PORT      VLESS/Reality port           (default: 443)
#   REALITY_SNI       Borrowed TLS domain          (default: www.microsoft.com)
#
#   HY2_PORT          Hysteria2 UDP port           (default: 443)
#   HY2_PASSWORD      Hysteria2 password           (default: random)
#   HY2_SNI           Cert CN when self-signed     (default: www.bing.com)
#   HY2_OBFS          1 = enable salamander obfuscation (default: 1)
#   ACME_EMAIL        Email for Hysteria2 ACME     (default: admin@$DOMAIN)
#
# Flags:
#   --uninstall       Remove the installed proxy, its service, config and firewall rule
#   --help            Show this header

set -euo pipefail

STATE_DIR=/etc/airport-tool
ENV_FILE="${STATE_DIR}/server.env"

### ── Config ────────────────────────────────────────────────────────────────── ###
PROTOCOL="${PROTOCOL:-shadowsocks}"
FORCE="${FORCE:-0}"
NO_BBR="${NO_BBR:-0}"

SS_PORT="${SS_PORT:-8388}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
DOMAIN="${DOMAIN:-}"
V2RAY_PLUGIN_MODE="${V2RAY_PLUGIN_MODE:-websocket}"

REALITY_PORT="${REALITY_PORT:-443}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"

HY2_PORT="${HY2_PORT:-443}"
HY2_SNI="${HY2_SNI:-www.bing.com}"
HY2_OBFS="${HY2_OBFS:-1}"
### ─────────────────────────────────────────────────────────────────────────── ###

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'; exit 0; }

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

# Read one value out of server.env without sourcing it — the file holds
# passwords and URIs that would be unsafe to run through the shell.
env_get() {
  local key="$1" line v
  [[ -f "$ENV_FILE" ]] || return 1
  line=$(grep -m1 "^${key}=" "$ENV_FILE" 2>/dev/null) || return 1
  v="${line#*=}"
  v="${v#\'}"; v="${v%\'}"
  printf '%s' "$v"
}

# Write KEY='value' safely (single quotes, with embedded quotes escaped).
env_put() {
  local key="$1" val="$2"
  printf "%s='%s'\n" "$key" "${val//\'/\'\\\'\'}"
}

### ── Arg parsing ───────────────────────────────────────────────────────────── ###
DO_UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --uninstall) DO_UNINSTALL=1 ;;
    --help|-h)   usage ;;
    *)           error "Unknown argument: $arg (try --help)" ;;
  esac
done

[[ $EUID -ne 0 ]] && error "Please run as root (sudo bash setup.sh)"

### ── Firewall ──────────────────────────────────────────────────────────────── ###
# Cloud images differ wildly here. Oracle Cloud and AWS ship an iptables INPUT
# chain that REJECTs everything except 22 and no ufw at all — the single most
# common reason a fresh server "installs fine" but never accepts a connection.
# So: use whichever firewall is actually active, and fall back to raw iptables.
persist_iptables() {
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
    return
  fi
  if [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
    return
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iptables-persistent >/dev/null 2>&1 || true
  if [[ -d /etc/iptables ]]; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
  else
    warn "Could not persist iptables rules — they may not survive a reboot."
  fi
}

ufw_active()      { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; }
firewalld_active() { command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; }

open_port() {
  local port="$1" proto="${2:-tcp}"
  if ufw_active; then
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${port}/${proto} failed"
    info "Opened ${port}/${proto} (ufw)"
  elif firewalld_active; then
    firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    info "Opened ${port}/${proto} (firewalld)"
  elif command -v iptables >/dev/null 2>&1; then
    # Insert at position 1 so we land ahead of the image's catch-all REJECT.
    if ! iptables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT 1 -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        warn "Could not add an iptables rule for ${port}/${proto} — open it yourself."
    fi
    if command -v ip6tables >/dev/null 2>&1; then
      ip6tables -C INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || \
        ip6tables -I INPUT 1 -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    fi
    persist_iptables
    info "Opened ${port}/${proto} (iptables)"
  else
    warn "No firewall tool found — open ${port}/${proto} yourself."
  fi
  warn "Also open ${port}/${proto} in your provider's security group / cloud firewall."
}

close_port() {
  local port="$1" proto="${2:-tcp}"
  if ufw_active; then
    ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
  elif firewalld_active; then
    firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  elif command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    command -v ip6tables >/dev/null 2>&1 && ip6tables -D INPUT -p "$proto" --dport "$port" -j ACCEPT 2>/dev/null || true
    persist_iptables
  fi
}

### ── Kernel / network tuning ───────────────────────────────────────────────── ###
# BBR is the single largest throughput win on a long-haul, lossy path — which is
# exactly what a link into China is. The buffer sizes also matter for Hysteria2:
# QUIC complains loudly about small UDP receive buffers.
enable_bbr() {
  [[ "$NO_BBR" == "1" ]] && { info "Skipping BBR (NO_BBR=1)"; return; }
  modprobe tcp_bbr 2>/dev/null || true
  if ! sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr; then
    warn "BBR is not available on kernel $(uname -r) — skipping tuning."
    return
  fi
  mkdir -p /etc/sysctl.d
  cat > /etc/sysctl.d/99-airport-tuning.conf <<'EOF'
# Installed by airport-tool setup.sh
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
# Large socket buffers: high bandwidth-delay product, and QUIC needs the UDP room.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
EOF
  sysctl --system >/dev/null 2>&1 || true
  info "Network tuning applied (congestion control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null))"
}

### ── Re-run safety ─────────────────────────────────────────────────────────── ###
# A second run used to silently mint new keys, breaking every client already
# carrying the old ones. Reuse what's on disk unless FORCE=1 says otherwise.
EXISTING_PROTOCOL="$(env_get PROTOCOL 2>/dev/null || true)"

REUSE=0
compute_reuse() {
if [[ -n "$EXISTING_PROTOCOL" && "$FORCE" != "1" ]]; then
  if [[ "$EXISTING_PROTOCOL" == "$PROTOCOL" ]] || \
     [[ "$EXISTING_PROTOCOL" == "reality" && "$PROTOCOL" == "vless" ]] || \
     [[ "$EXISTING_PROTOCOL" == "shadowsocks" && "$PROTOCOL" == "ss" ]]; then
    REUSE=1
    info "Existing ${EXISTING_PROTOCOL} setup found — reusing its keys/passwords."
    info "Run with FORCE=1 to generate new ones (this invalidates every existing client)."
  else
    warn "A ${EXISTING_PROTOCOL} setup already exists; installing ${PROTOCOL} alongside it."
  fi
fi
}

#############################################################################
# Uninstall
#############################################################################
do_uninstall() {
  local proto="${EXISTING_PROTOCOL:-$PROTOCOL}"
  info "Uninstalling ${proto}..."
  case "$proto" in
    shadowsocks|ss)
      systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/shadowsocks-libev.service
      rm -rf /etc/shadowsocks-libev
      rm -f /etc/letsencrypt/renewal-hooks/deploy/airport-ss.sh
      rm -f /usr/local/bin/v2ray-plugin
      apt-get remove -y -qq shadowsocks-libev >/dev/null 2>&1 || true
      close_port "$(env_get SS_PORT || echo "$SS_PORT")" tcp
      ;;
    reality|vless)
      systemctl disable --now xray >/dev/null 2>&1 || true
      bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge >/dev/null 2>&1 || true
      close_port "$(env_get REALITY_PORT || echo "$REALITY_PORT")" tcp
      ;;
    hysteria2|hy2)
      systemctl disable --now hysteria-server.service >/dev/null 2>&1 || true
      bash <(curl -fsSL https://get.hy2.sh/) --remove >/dev/null 2>&1 || true
      rm -rf /etc/hysteria
      close_port "$(env_get HY2_PORT || echo "$HY2_PORT")" udp
      close_port "$(env_get HY2_PORT || echo "$HY2_PORT")" tcp
      ;;
    *) warn "Nothing recorded in ${ENV_FILE}; removing state only." ;;
  esac
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -f /etc/sysctl.d/99-airport-tuning.conf
  rm -rf "$STATE_DIR"
  info "Uninstalled. Port 22 and your provider's firewall were left untouched."
  exit 0
}

# Uninstall dispatches here rather than at the bottom: bash resolves a function
# name only when the call actually executes, so this has to sit below the
# definition above. Running it before compute_reuse also keeps `--uninstall`
# from first announcing that it's installing something.
[[ $DO_UNINSTALL -eq 1 ]] && do_uninstall
compute_reuse

### ── Environment probe ─────────────────────────────────────────────────────── ###
ARCH=$(uname -m)
OS_ID=$(. /etc/os-release && echo "$ID")
info "OS: $OS_ID | Arch: $ARCH | Protocol: $PROTOCOL"

SERVER_IP=$(curl -s4 --max-time 8 https://ifconfig.me 2>/dev/null || true)
if [[ -z "$SERVER_IP" ]]; then
  SERVER_IP=$(curl -s6 --max-time 8 https://ifconfig.me 2>/dev/null || true)
  [[ -n "$SERVER_IP" ]] && warn "Only an IPv6 address was found — clients on IPv4-only networks won't reach this server."
fi
[[ -z "$SERVER_IP" ]] && SERVER_IP=$(hostname -I | awk '{print $1}')
[[ -z "$SERVER_IP" ]] && error "Could not determine this server's public IP."
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

#############################################################################
# Shadowsocks + v2ray-plugin
#############################################################################
setup_shadowsocks() {
  # Reuse the existing password so already-distributed clients keep working.
  if [[ $REUSE -eq 1 && -z "${SS_PASSWORD:-}" ]]; then
    SS_PASSWORD="$(env_get SS_PASSWORD || true)"
  fi
  SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 16)}"

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
  # mode is tcp_only on purpose: v2ray-plugin's WebSocket transport carries no
  # UDP, so a udp mode here would advertise relaying it can't do. If you need
  # UDP (QUIC, games, some voice apps), use PROTOCOL=hysteria2 instead.
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
  chmod 600 /etc/shadowsocks-libev/config.json

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

  open_port "$SS_PORT"
  verify_service shadowsocks-libev

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

  {
    env_put PROTOCOL shadowsocks
    env_put SS_SERVER "$SS_HOST"
    env_put SS_PORT "$SS_PORT"
    env_put SS_PASSWORD "$SS_PASSWORD"
    env_put SS_METHOD "$SS_METHOD"
    env_put SS_PLUGIN v2ray-plugin
    env_put SS_PLUGIN_OPTS "$SERVER_OPTS"
    env_put SS_URI "$SS_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  # Emit a ready-to-use profile for servers.json / the web UI.
  cat > "${STATE_DIR}/profile.json" <<PJEOF
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
  chmod 600 "${STATE_DIR}/profile.json"
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

  # Reality borrows the target site's TLS handshake, so that site must actually
  # speak TLS 1.3 — otherwise the camouflage fails and the connection stands out.
  if ! echo | timeout 8 openssl s_client -connect "${REALITY_SNI}:443" \
        -servername "${REALITY_SNI}" -tls1_3 >/dev/null 2>&1; then
    warn "${REALITY_SNI} did not complete a TLS 1.3 handshake — it is a poor Reality target."
    warn "Pick a site that supports TLS 1.3 + HTTP/2 (e.g. www.microsoft.com, www.amazon.com)."
  fi

  local priv pub uuid sid keypair
  if [[ $REUSE -eq 1 ]]; then
    priv="$(env_get REALITY_PRIVATE_KEY || true)"
    pub="$(env_get REALITY_PUBLIC_KEY || true)"
    uuid="$(env_get REALITY_UUID || true)"
    sid="$(env_get REALITY_SHORT_ID || true)"
  fi
  if [[ -z "${priv:-}" || -z "${pub:-}" || -z "${uuid:-}" || -z "${sid:-}" ]]; then
    info "Generating Reality keys, UUID and short ID..."
    keypair=$(xray x25519)
    priv=$(echo "$keypair" | awk '/[Pp]rivate key:/ {print $3}')
    pub=$(echo  "$keypair" | awk '/[Pp]ublic key:/ {print $3}')
    uuid=$(xray uuid)
    sid=$(openssl rand -hex 8)
    [[ -z "$priv" || -z "$pub" ]] && error "Could not parse the keypair from 'xray x25519'."
  else
    info "Reusing the existing UUID and Reality keypair."
  fi

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
  chmod 600 /usr/local/etc/xray/config.json

  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray

  open_port "$REALITY_PORT"
  verify_service xray

  # Build the vless:// URI.
  REALITY_URI="vless://${uuid}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${pub}&sid=${sid}&type=tcp#Airport%20Reality"

  print_result "VLESS + Reality" \
    "Server=${SERVER_IP}" "Port=${REALITY_PORT}" "UUID=${uuid}" \
    "PublicKey=${pub}" "ShortID=${sid}" "SNI=${REALITY_SNI}"
  echo "  URI: $REALITY_URI"

  {
    env_put PROTOCOL reality
    env_put REALITY_SERVER "$SERVER_IP"
    env_put REALITY_PORT "$REALITY_PORT"
    env_put REALITY_UUID "$uuid"
    env_put REALITY_PUBLIC_KEY "$pub"
    # Stored so a re-run can reuse it instead of invalidating every client.
    env_put REALITY_PRIVATE_KEY "$priv"
    env_put REALITY_SHORT_ID "$sid"
    env_put REALITY_SNI "$REALITY_SNI"
    env_put REALITY_URI "$REALITY_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  cat > "${STATE_DIR}/profile.json" <<PJEOF
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
  chmod 600 "${STATE_DIR}/profile.json"
}

#############################################################################
# Hysteria2 (QUIC / UDP)
#############################################################################
# Worth having alongside the TCP protocols: China ingress paths are lossy and
# heavily shaped, and Hysteria2's congestion control plus a real UDP transport
# hold up where a TCP tunnel collapses. It also actually relays UDP, which the
# Shadowsocks + v2ray-plugin combination cannot.
setup_hysteria2() {
  if [[ $REUSE -eq 1 ]]; then
    HY2_PASSWORD="${HY2_PASSWORD:-$(env_get HY2_PASSWORD || true)}"
    HY2_OBFS_PASSWORD="${HY2_OBFS_PASSWORD:-$(env_get HY2_OBFS_PASSWORD || true)}"
  fi
  HY2_PASSWORD="${HY2_PASSWORD:-$(openssl rand -base64 18)}"
  HY2_OBFS_PASSWORD="${HY2_OBFS_PASSWORD:-$(openssl rand -base64 18)}"

  info "Installing Hysteria2..."
  apt-get update -qq
  apt-get install -y -qq curl openssl
  bash <(curl -fsSL https://get.hy2.sh/) >/dev/null 2>&1 || error "Hysteria2 install failed."

  mkdir -p /etc/hysteria
  local tls_block sni insecure
  if [[ -n "$DOMAIN" ]]; then
    info "ACME mode: Hysteria2 will obtain a real certificate for ${DOMAIN}."
    open_port 80 tcp   # http-01 challenge
    tls_block="acme:
  domains:
    - ${DOMAIN}
  email: ${ACME_EMAIL:-admin@${DOMAIN}}"
    sni="$DOMAIN"
    insecure="false"
  else
    info "Self-signed certificate mode (CN=${HY2_SNI})."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt \
      -subj "/CN=${HY2_SNI}" -days 3650 >/dev/null 2>&1 || error "Could not generate a self-signed certificate."
    chown hysteria:hysteria /etc/hysteria/server.key /etc/hysteria/server.crt 2>/dev/null || true
    chmod 600 /etc/hysteria/server.key
    tls_block="tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key"
    sni="$HY2_SNI"
    insecure="true"
    warn "Self-signed cert — clients must set insecure/skip-cert-verify. Set DOMAIN=… for a real one."
  fi

  local obfs_block=""
  if [[ "$HY2_OBFS" == "1" ]]; then
    obfs_block="obfs:
  type: salamander
  salamander:
    password: ${HY2_OBFS_PASSWORD}"
  else
    HY2_OBFS_PASSWORD=""
  fi

  info "Writing Hysteria2 config..."
  cat > /etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

${tls_block}

auth:
  type: password
  password: ${HY2_PASSWORD}

${obfs_block}

# Anything that probes the port without valid credentials gets a plausible
# website instead of a protocol error — that's the camouflage.
masquerade:
  type: proxy
  proxy:
    url: https://${sni}/
    rewriteHost: true

quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
EOF
  chmod 600 /etc/hysteria/config.yaml
  chown hysteria:hysteria /etc/hysteria/config.yaml 2>/dev/null || true

  systemctl enable hysteria-server.service >/dev/null 2>&1 || true
  systemctl restart hysteria-server.service

  # QUIC is UDP; the TCP rule most images already have does nothing for it.
  open_port "$HY2_PORT" udp
  verify_service hysteria-server

  # Build the query piece by piece. Note: a command substitution that exits
  # non-zero aborts the whole assignment under `set -e`, so no inline
  # `$( [[ … ]] && echo … )` here — the empty case would kill the script.
  local auth_enc obfs_q="" insecure_q=""
  auth_enc=$(urlencode "$HY2_PASSWORD")
  if [[ "$HY2_OBFS" == "1" ]]; then
    obfs_q="&obfs=salamander&obfs-password=$(urlencode "$HY2_OBFS_PASSWORD")"
  fi
  if [[ "$insecure" == "true" ]]; then
    insecure_q="&insecure=1"
  fi
  HY2_URI="hysteria2://${auth_enc}@${SERVER_IP}:${HY2_PORT}/?sni=${sni}${insecure_q}${obfs_q}#Airport%20Hysteria2"

  print_result "Hysteria2" \
    "Server=${SERVER_IP}" "Port=${HY2_PORT} (UDP)" "Password=${HY2_PASSWORD}" \
    "SNI=${sni}" "Insecure=${insecure}" \
    "Obfs=$( [[ "$HY2_OBFS" == "1" ]] && echo "salamander / ${HY2_OBFS_PASSWORD}" || echo "off" )"
  echo "  URI: $HY2_URI"

  {
    env_put PROTOCOL hysteria2
    env_put HY2_SERVER "$SERVER_IP"
    env_put HY2_PORT "$HY2_PORT"
    env_put HY2_PASSWORD "$HY2_PASSWORD"
    env_put HY2_SNI "$sni"
    env_put HY2_INSECURE "$insecure"
    env_put HY2_OBFS "$HY2_OBFS"
    env_put HY2_OBFS_PASSWORD "$HY2_OBFS_PASSWORD"
    env_put HY2_URI "$HY2_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  cat > "${STATE_DIR}/profile.json" <<PJEOF
{
  "protocol": "hysteria2",
  "server": "${SERVER_IP}",
  "port": ${HY2_PORT},
  "password": "${HY2_PASSWORD}",
  "sni": "${sni}",
  "insecure": ${insecure},
  "obfs": "$( [[ "$HY2_OBFS" == "1" ]] && echo "salamander" )",
  "obfsPassword": "${HY2_OBFS_PASSWORD}",
  "remarks": "Airport Hysteria2"
}
PJEOF
  chmod 600 "${STATE_DIR}/profile.json"
}

# ── Post-install sanity check ───────────────────────────────────────────────── #
# Fail loudly here rather than let the user discover it from a client that just
# won't connect.
verify_service() {
  local unit="$1"
  sleep 2
  if systemctl is-active --quiet "$unit"; then
    info "${unit} is running."
  else
    warn "${unit} is NOT running. Recent log:"
    journalctl -u "$unit" -n 20 --no-pager 2>/dev/null || true
    error "Setup finished but ${unit} failed to start — fix the above before using these details."
  fi
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
open_port 22   # never lock yourself out
enable_bbr

case "$PROTOCOL" in
  shadowsocks|ss)  setup_shadowsocks ;;
  reality|vless)   setup_reality ;;
  hysteria2|hy2)   setup_hysteria2 ;;
  *)               error "Unknown PROTOCOL: $PROTOCOL (use 'shadowsocks', 'reality' or 'hysteria2')" ;;
esac

echo -e "${GREEN}  Config + client profile saved to ${STATE_DIR}/${NC}"
echo -e "${YELLOW}  A ready-to-import profile is at ${STATE_DIR}/profile.json${NC}"
echo -e "${YELLOW}  Import it on your PC with:  node gen.js --add /path/to/profile.json${NC}"
echo -e "${YELLOW}  (or paste it into the web UI's Import box)${NC}"
echo ""
