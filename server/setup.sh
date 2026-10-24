#!/usr/bin/env bash
# Airport server setup — Shadowsocks (v2ray-plugin), VLESS + Reality, Hysteria2
# or TUIC v5.
# Tested on Ubuntu 20.04/22.04/24.04 and Debian 11/12.
#
# Run as root:  sudo bash setup.sh
#   or:  PROTOCOL=reality bash <(curl -sL <url>)
#
# Env knobs:
#   PROTOCOL          shadowsocks | reality | hysteria2 | tuic  (default: shadowsocks)
#   FORCE             1 = regenerate keys/passwords even if a setup already exists
#   NO_BBR            1 = skip the BBR / network tuning step
#
#   SERVER_IP         Public address to put in client links (default: detected).
#                     Set it when the detection below gets it wrong — behind NAT,
#                     or on a VPS whose only interface address is a private one.
#
#   XRAY_VERSION      Xray release to install      (default: pinned, see below)
#   HY2_VERSION       Hysteria2 release to install (default: pinned)
#   SINGBOX_VERSION   sing-box release to install  (default: pinned)
#                     Each installer used to fetch whatever was newest, so the
#                     same script installed different software from one week to
#                     the next. Set one to "latest" to opt back into that.
#   ALLOW_UNPINNED_INSTALLERS
#                     1 = run the upstream installer scripts from their moving
#                     URLs without checking them (default: off). Only for when a
#                     pinned installer no longer works with a newer *_VERSION.
#
#   SS_PORT           Shadowsocks port             (default: 8388)
#   SS_PASSWORD       Shadowsocks password         (default: random)
#   SS_METHOD         Shadowsocks cipher           (default: chacha20-ietf-poly1305)
#                     A 2022-blake3-* cipher installs Shadowsocks 2022 on
#                     sing-box instead of shadowsocks-libev (which has no 2022
#                     support): no plugin, TCP and UDP, and SS_PASSWORD must be
#                     a base64 key of the cipher's length (generated if unset).
#   DOMAIN            Domain for real TLS — Shadowsocks TLS mode / Hysteria2 ACME
#   V2RAY_PLUGIN_MODE websocket | tls              (default: websocket)
#
#   REALITY_PORT      VLESS/Reality port           (default: 443)
#   REALITY_SNI       Borrowed TLS domain          (default: www.microsoft.com)
#   REALITY_NETWORK   tcp | grpc | xhttp           (default: tcp)
#   REALITY_PATH      gRPC serviceName / XHTTP path (default: random)
#
#   HY2_PORT          Hysteria2 UDP port           (default: 443)
#   HY2_PASSWORD      Hysteria2 password           (default: random)
#   HY2_SNI           Cert CN when self-signed     (default: www.bing.com)
#   HY2_OBFS          1 = enable salamander obfuscation (default: 1)
#   HY2_PORT_RANGE    UDP range to hop across, e.g. 20000-30000 (default: off)
#   HY2_UP            Client upload rate, Mbps     (default: unset)
#   HY2_DOWN          Client download rate, Mbps   (default: unset)
#                     Both are needed to switch on Brutal congestion control, which
#                     is most of the reason to run Hysteria2 on a lossy path. They
#                     describe the client's link, not this server's — guess low.
#   HY2_MASQUERADE    Site shown to unauthenticated probes (default: www.bing.com).
#                     Must be an *external* site — never this server's own domain.
#   ACME_EMAIL        Email for Hysteria2 ACME     (default: admin@$DOMAIN)
#
#   TUIC_PORT         TUIC UDP port                (default: 443)
#   TUIC_UUID         TUIC UUID                    (default: random)
#   TUIC_PASSWORD     TUIC password                (default: random)
#   TUIC_SNI          Cert CN when self-signed     (default: www.bing.com)
#
# Each protocol keeps its own state in ${STATE_DIR}/<protocol>.env, so you can
# run several side by side and remove one without disturbing the others.
#
# Re-running with no environment set reuses everything recorded there — keys,
# passwords, ports and SNI alike — so existing clients keep working. Pass a
# variable explicitly to change it, or FORCE=1 to regenerate the secrets.
#
# Flags:
#   --show            Print every installed protocol's details and exit (changes nothing)
#   --show --json     Same, as a JSON array of client profiles and nothing else,
#                     so it can be piped straight into the generator:
#                       ssh root@vps 'bash setup.sh --show --json' | node gen.js --add -
#   --uninstall       Remove one proxy, its service, config and firewall rules.
#                     Names it via PROTOCOL=…; with exactly one installed you can
#                     leave PROTOCOL unset.
#   --doctor          Check every installed protocol — service running, port
#                     listening, firewall rule present, hop redirect intact,
#                     certificate expiry, config readable by the service — and
#                     exit non-zero if anything is wrong. Changes nothing.
#   --upgrade         Reinstall the pinned (or *_VERSION-selected) Xray, Hysteria2
#                     and sing-box for whatever is installed, and restart them.
#                     Keys, configs and firewall rules are left as they are.
#   --export-state FILE
#                     Write a tarball (mode 600) of every installed protocol's
#                     state, keys and certificates — for moving to a new VPS.
#   --import-state FILE
#                     Restore such a tarball here and re-run setup for each
#                     protocol in it, reusing its keys so clients keep working.
#                     Refuses to replace a different install unless --force.
#                     Run it from a saved copy of this script, not from a pipe.
#   --help            Show this header

set -euo pipefail

STATE_DIR=/etc/airport-tool
# Every protocol keeps its own state file. They used to share one server.env,
# so installing a second protocol "alongside" the first truncated the first
# one's keys out of existence — and --show and --uninstall could then no longer
# see it at all. The shared file is still read once, to migrate it.
LEGACY_ENV_FILE="${STATE_DIR}/server.env"

### ── Config ────────────────────────────────────────────────────────────────── ###
# Whether the caller *named* a protocol matters for --uninstall, which must not
# guess "shadowsocks" just because that is the install default.
PROTOCOL_EXPLICIT=0
[[ -n "${PROTOCOL:-}" ]] && PROTOCOL_EXPLICIT=1
PROTOCOL="${PROTOCOL:-shadowsocks}"
FORCE="${FORCE:-0}"
NO_BBR="${NO_BBR:-0}"

# Anything the caller set explicitly is recorded here *before* the saved values
# are folded in, so compute_reuse() can tell "the user asked for port 8443" apart
# from "8388 is just the default". Getting that wrong is how a plain re-run used
# to silently move the server to a different port and orphan every client.
EXPLICIT_VARS=""
for v in SS_PORT SS_METHOD SS_PASSWORD DOMAIN V2RAY_PLUGIN_MODE \
         REALITY_PORT REALITY_SNI REALITY_NETWORK REALITY_PATH \
         HY2_PORT HY2_SNI HY2_OBFS HY2_PASSWORD HY2_OBFS_PASSWORD HY2_PORT_RANGE \
         HY2_UP HY2_DOWN \
         HY2_MASQUERADE ACME_EMAIL \
         TUIC_PORT TUIC_UUID TUIC_PASSWORD TUIC_SNI; do
  if [[ -n "${!v:-}" ]]; then EXPLICIT_VARS="${EXPLICIT_VARS} ${v}"; fi
done

SS_PORT="${SS_PORT:-8388}"
SS_METHOD="${SS_METHOD:-chacha20-ietf-poly1305}"
DOMAIN="${DOMAIN:-}"
V2RAY_PLUGIN_MODE="${V2RAY_PLUGIN_MODE:-websocket}"

REALITY_PORT="${REALITY_PORT:-443}"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"
REALITY_NETWORK="${REALITY_NETWORK:-tcp}"
REALITY_PATH="${REALITY_PATH:-}"

HY2_PORT="${HY2_PORT:-443}"
HY2_SNI="${HY2_SNI:-www.bing.com}"
HY2_OBFS="${HY2_OBFS:-1}"
# The site an unauthenticated prober is shown instead of a protocol error. It
# has to be somewhere else: pointing it at this server's own domain — which is
# what using $sni did in ACME mode — makes Hysteria2 fetch a page from a TCP
# port it is not listening on, so the camouflage serves an error and the probe
# learns that something unusual lives here after all.
HY2_MASQUERADE="${HY2_MASQUERADE:-www.bing.com}"

TUIC_PORT="${TUIC_PORT:-443}"
TUIC_SNI="${TUIC_SNI:-www.bing.com}"

# Hysteria2 port hopping. The server publishes a whole UDP range and NATs it
# back to the real port; the client rotates across it. That survives a block
# aimed at one port, and a shaper that latches onto a single UDP flow.
HY2_PORT_RANGE="${HY2_PORT_RANGE:-}"

# Declared link speed in Mbps, written into the client URI and profile.json.
# Hysteria2's Brutal congestion controller sends at the rate the client declares
# rather than one it infers from loss, which is the whole reason to pick it for a
# path that makes TCP collapse. A client that declares nothing falls back to BBR
# without saying so — which is what every profile this script wrote used to do.
# Both halves are required: one alone is not a rate, and clients disagree about
# whether the missing half means zero or unlimited.
HY2_UP="${HY2_UP:-}"
HY2_DOWN="${HY2_DOWN:-}"

# The releases this script was tested against. *_VERSION picks the binary each
# upstream installer fetches; "latest" lets the installer choose.
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
HY2_VERSION="${HY2_VERSION:-v2.12.3}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.14.2}"

# The installer scripts themselves, pinned to one commit each and checked
# against a sha256 before they run as root. They used to be piped straight
# from a moving URL into bash — raw/main of Xray-install, get.hy2.sh and
# sing-box.app — so whoever controlled those that day (or anything between
# here and them) ran code as root on every server installed, and *_VERSION
# only pinned what the script chose to download afterwards. Now a script that
# does not hash to exactly what was reviewed is refused before a line of it
# runs. The v2ray-plugin tarball further down has always been checked this way.
#
# get.hy2.sh is a redirect to HyNetworks/hysteria (formerly apernet/hysteria)
# scripts/install_server.sh; sing-box.app/install.sh serves SagerNet/sing-box
# docs/installation/tools/install.sh. Pinning the repository files gives the
# same scripts at an address that cannot change underneath us. To move a pin:
# fetch the new commit's file, read it, and replace both the URL and the hash.
XRAY_INSTALLER_URL="https://raw.githubusercontent.com/XTLS/Xray-install/05aa47266c94e6fb5ca48cad96afdb4becb5891f/install-release.sh"
XRAY_INSTALLER_SHA256="65e9e2accfc0b3b5dd24e7f2c552f35af3e581068155163d66d40f1d04fb6c95"
HY2_INSTALLER_URL="https://raw.githubusercontent.com/HyNetworks/hysteria/e1d3132ef4f33d310c0cf85ba81040c5d7e0a6d8/scripts/install_server.sh"
HY2_INSTALLER_SHA256="2cc5d1c62f132f30c07e75d972144aa5d61ef59f547a04a537e2d9ac505b4344"
SINGBOX_INSTALLER_URL="https://raw.githubusercontent.com/SagerNet/sing-box/8289bbd846e04da8098acfd1554c17c057c1060f/docs/installation/tools/install.sh"
SINGBOX_INSTALLER_SHA256="528b3c77d2510558d2e542e709e19ef1fba445a7dfc5ad7e0e0559bd854fb108"
# The moving addresses, used only under ALLOW_UNPINNED_INSTALLERS=1.
XRAY_INSTALLER_LATEST="https://github.com/XTLS/Xray-install/raw/main/install-release.sh"
HY2_INSTALLER_LATEST="https://get.hy2.sh/"
SINGBOX_INSTALLER_LATEST="https://sing-box.app/install.sh"
ALLOW_UNPINNED_INSTALLERS="${ALLOW_UNPINNED_INSTALLERS:-0}"
### ─────────────────────────────────────────────────────────────────────────── ###

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
# Progress and diagnostics go to stderr, so stdout carries only what the script
# was asked to produce. Without this `--show --json | node gen.js --add -` gets
# a state-migration notice spliced into the middle of its JSON.
info()  { echo -e "${GREEN}[INFO]${NC} $*" >&2; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'; exit 0; }

# One spelling per protocol, so state file names and case branches never drift.
canon_protocol() {
  case "$1" in
    shadowsocks|ss) printf 'shadowsocks' ;;
    reality|vless)  printf 'reality' ;;
    hysteria2|hy2)  printf 'hysteria2' ;;
    tuic)           printf 'tuic' ;;
    *)              return 1 ;;
  esac
}

# Which protocols have state on this box, one per line.
installed_protocols() {
  local f base
  for f in "${STATE_DIR}"/*.env; do
    [[ -e "$f" ]] || continue
    base=$(basename "$f" .env)
    canon_protocol "$base" >/dev/null 2>&1 && echo "$base"
  done
  # Without this the status is the last test's: a stray unrecognised *.env
  # sorting last made `installed=$(installed_protocols)` abort under set -e.
  return 0
}

# Bracket a bare IPv6 literal for use in a URI authority — the same rule as
# hostForUri() in config-gen/lib/configs.js. Without it an IPv6-only VPS (the
# case the public-IP probe below explicitly warns about) printed URIs shaped
# like ss://...@2001:db8::1:8388, which no client can parse: the last colon
# reads as part of the address rather than as the port separator.
uri_host() {
  local h="$1"
  if [[ "$h" == *:* && "$h" != \[* ]]; then printf '[%s]' "$h"; else printf '%s' "$h"; fi
}

# ── Address literals ───────────────────────────────────────────────────────── #
# The server address is written unquoted into URIs and profile.json, so it is
# held to being an address literal rather than escaped.
valid_ipv4() {
  local ip="$1" o
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
}
valid_ipv6() {
  local ip="$1" rest groups
  [[ ${#ip} -le 45 && "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ ]] || return 1
  # At most one "::", and no ":::".
  rest="${ip#*::}"; [[ "$rest" == *::* || "$ip" == *:::* ]] && return 1
  # An embedded IPv4 tail (::ffff:192.0.2.1) has to be a real one.
  if [[ "$ip" == *.* ]]; then valid_ipv4 "${ip##*:}" || return 1; fi
  groups=$(printf '%s' "${ip%%.*}" | tr ':' '\n' | grep -c . || true)
  (( groups <= 8 )) || return 1
  [[ "$ip" == *::* ]] || (( groups == 8 )) || [[ "$ip" == *.* ]] || return 1
  printf '%s' "$ip" | tr ':' '\n' | awk 'length($0) > 4 && $0 !~ /\./ { bad=1 } END { exit bad }'
}
valid_ip() { valid_ipv4 "$1" || valid_ipv6 "$1"; }

# Private, CGNAT, loopback and link-local: addresses no client on the internet
# can dial, which hostname -I hands back on any VPS behind NAT.
is_private_ip() {
  local ip="$1" a b
  if valid_ipv4 "$ip"; then
    a="${ip%%.*}"; b="${ip#*.}"; b="${b%%.*}"
    (( a == 10 || a == 127 )) && return 0
    (( a == 172 && b >= 16 && b <= 31 )) && return 0
    (( a == 192 && b == 168 )) && return 0
    (( a == 100 && b >= 64 && b <= 127 )) && return 0
    (( a == 169 && b == 254 )) && return 0
    return 1
  fi
  ip=$(printf '%s' "$ip" | tr 'A-F' 'a-f')
  [[ "$ip" == "::1" ]] && return 0
  [[ "$ip" =~ ^f[cd] ]] && return 0            # fc00::/7
  [[ "$ip" =~ ^fe[89ab] ]] && return 0         # fe80::/10
  return 1
}

# Ask each echo service in turn for this machine's address over IPv$1; print
# the first answer that is an address of that family.
probe_ip() {
  local fam="$1" svc out; shift
  for svc in "$@"; do
    out=$(curl -fsS -"$fam" --max-time 8 "$svc" 2>/dev/null | tr -d '[:space:]') || out=""
    if [[ "$fam" == 4 ]] && valid_ipv4 "$out"; then printf '%s' "$out"; return 0; fi
    if [[ "$fam" == 6 ]] && valid_ipv6 "$out"; then printf '%s' "$out"; return 0; fi
  done
  return 1
}

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

# /proc is Linux-only and uuidgen is not always installed; openssl is a hard
# dependency of every path here, which makes it the dependable fallback.
gen_uuid() {
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  elif command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr 'A-Z' 'a-z'
  else
    local h; h=$(openssl rand -hex 16)
    printf '%s-%s-%s-%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
  fi
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

# ── Quoting values into the files this script writes ───────────────────────── #
# Passwords can be chosen by the caller (SS_PASSWORD=…), and they used to be
# pasted straight into JSON and YAML heredocs. A password holding a double
# quote or a backslash produced a config.json the server refused to parse —
# after the old one had already been overwritten — and a colon or a # in the
# Hysteria2 password silently changed what the YAML meant.

# A JSON string literal, quotes included. Control characters are refused
# before anything reaches here (see check_secret), so these escapes are all
# the ones a password can need.
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  printf '"%s"' "$s"
}

# A single-quoted YAML scalar: the only escape inside one is '' for '.
yaml_str() {
  local s="$1"
  printf "'%s'" "${s//\'/\'\'}"
}

# ── Validating what the caller passed in ────────────────────────────────────── #
check_port() {
  local name="$1" v="$2"
  if ! [[ "$v" =~ ^[0-9]+$ ]] || (( v < 1 || v > 65535 )); then
    error "${name}=${v} is not a port (1-65535)."
  fi
}

# Hostnames land in JSON, YAML and URIs unquoted in places, so they are held to
# what a hostname can actually be rather than escaped.
HOSTNAME_RE='^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$'
check_hostname() {
  local name="$1" v="$2"
  [[ -z "$v" ]] && return 0
  [[ "$v" =~ $HOSTNAME_RE ]] || error "${name}=${v} is not a hostname."
}

# A secret may contain anything printable; a newline or other control character
# can only be a paste accident, and it would split the line it lands on.
check_secret() {
  local name="$1" v="$2"
  [[ -z "$v" ]] && return 0
  [[ "$v" =~ [[:cntrl:]] ]] && error "${name} contains a control character (a stray newline?)."
  return 0
}

# ── Shadowsocks 2022 keys ──────────────────────────────────────────────────── #
# A 2022 cipher takes a base64 key of an exact length, not a passphrase — the
# same rule ss2022KeyError() enforces in config-gen/lib/configs.js.
ss2022_key_len() {
  case "$1" in
    2022-blake3-aes-128-gcm) printf '16' ;;
    *) printf '32' ;;
  esac
}

# True when $1 is canonical base64 of exactly $2 bytes. Round-tripped rather
# than pattern-matched: base64 -d skips characters it does not recognise.
ss2022_key_ok() {
  local key="$1" want="$2" got back
  got=$(printf '%s' "$key" | base64 -d 2>/dev/null | wc -c | tr -d '[:space:]') || return 1
  back=$(printf '%s' "$key" | base64 -d 2>/dev/null | base64 | tr -d '\n') || return 1
  [[ "$got" == "$want" && "$back" == "$key" ]]
}

# Make a root-owned secret readable by a service that runs as `nobody`, and by
# nobody else. Debian and Ubuntu call that group nogroup; most others, nobody.
nobody_group_owns() {
  local f="$1"
  chown root:nogroup "$f" 2>/dev/null || chown root:nobody "$f" 2>/dev/null || true
  chmod 640 "$f"
}

# ── Listening on both stacks, or on the one the kernel has ─────────────────── #
# "::" accepts IPv4 too on a dual-stack kernel, which is what made an IPv6-only
# VPS work at all. On a kernel booted with IPv6 disabled — a common VPS image
# setting — there is no "::" to bind, and shadowsocks-libev exits on start.
listen_any() {
  if [[ -r /proc/net/if_inet6 ]] && [[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 0)" != "1" ]]; then
    printf '::'
  else
    printf '0.0.0.0'
  fi
}

### ── Arg parsing ───────────────────────────────────────────────────────────── ###
DO_UNINSTALL=0
DO_SHOW=0
DO_JSON=0
DO_DOCTOR=0
DO_UPGRADE=0
DO_FORCE_IMPORT=0
EXPORT_FILE=""
IMPORT_FILE=""
while [[ $# -gt 0 ]]; do
  arg="$1"; shift
  case "$arg" in
    --uninstall) DO_UNINSTALL=1 ;;
    --show)      DO_SHOW=1 ;;
    --json)      DO_JSON=1 ;;
    --doctor)    DO_DOCTOR=1 ;;
    --upgrade)   DO_UPGRADE=1 ;;
    # Spelled out rather than reusing FORCE=1, which means "mint new secrets" —
    # the one thing an import exists to avoid.
    --force)     DO_FORCE_IMPORT=1 ;;
    --export-state|--import-state)
      [[ $# -gt 0 && -n "$1" && "$1" != --* ]] || error "${arg} needs a file name (e.g. ${arg} /root/airport-state.tgz)"
      if [[ "$arg" == --export-state ]]; then EXPORT_FILE="$1"; else IMPORT_FILE="$1"; fi
      shift ;;
    --export-state=*) EXPORT_FILE="${arg#*=}" ;;
    --import-state=*) IMPORT_FILE="${arg#*=}" ;;
    --help|-h)   usage ;;
    *)           error "Unknown argument: $arg (try --help)" ;;
  esac
done
# --json only means anything alongside --show. Silently ignoring it on an
# install run would be a good way to pipe an installer's chatter into a parser.
[[ $DO_JSON -eq 1 && $DO_SHOW -eq 0 ]] && error "--json only applies to --show (try: bash setup.sh --show --json)"
[[ $DO_FORCE_IMPORT -eq 1 && -z "$IMPORT_FILE" ]] && error "--force only applies to --import-state."
# One action per run: "--doctor --uninstall" has no order that would be safe to guess.
_actions=$(( DO_UNINSTALL + DO_SHOW + DO_DOCTOR + DO_UPGRADE ))
[[ -n "$EXPORT_FILE" ]] && _actions=$(( _actions + 1 ))
[[ -n "$IMPORT_FILE" ]] && _actions=$(( _actions + 1 ))
(( _actions <= 1 )) || error "Pick one of --show, --uninstall, --doctor, --upgrade, --export-state, --import-state per run."

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
  # iptables-persistent declares a conflict with ufw (and fights firewalld for
  # the same job), so installing it on a box running either has apt *remove*
  # the firewall to make room — taking every rule it held with it. Those boxes
  # persist their own rules; anything this script needs at boot beyond that
  # (the Hysteria2 hop redirect) gets its own unit instead.
  if command -v ufw >/dev/null 2>&1 || command -v firewall-cmd >/dev/null 2>&1; then
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

# ── Port range dialects ─────────────────────────────────────────────────────── #
# The three firewalls do not agree on how to write a range, and passing the
# wrong one is rejected rather than approximated:
#
#   ufw       20000:30000/udp
#   iptables  --dport 20000:30000
#   firewalld --add-port=20000-30000/udp
#
# Callers hand over either spelling and each tool is given the one it parses.
# Port hopping used to pass the dash form to all three, so on ufw and on the
# raw-iptables path — which is every Oracle Cloud and AWS image, the ones this
# script exists for — the rule was refused while the script reported success.
#
# The substitution is global (`//`, not `/`). It only ever saw one separator at a
# time, so the single form was enough until a comma-separated range arrived —
# at which point "20000-30000,40000-40010" became "20000:30000,40000-40010" and
# the firewall refused half of it.
colon_ports() { printf '%s' "${1//-/:}"; }
dash_ports()  { printf '%s' "${1//:/-}"; }

open_port() {
  local port="$1" proto="${2:-tcp}" colon dash
  colon="$(colon_ports "$port")"
  dash="$(dash_ports "$port")"
  if ufw_active; then
    ufw allow "${colon}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${colon}/${proto} failed"
    info "Opened ${colon}/${proto} (ufw)"
  elif firewalld_active; then
    firewall-cmd --permanent --add-port="${dash}/${proto}" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    info "Opened ${dash}/${proto} (firewalld)"
  elif command -v iptables >/dev/null 2>&1; then
    # Insert at position 1 so we land ahead of the image's catch-all REJECT.
    if ! iptables -C INPUT -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT 1 -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null || \
        warn "Could not add an iptables rule for ${colon}/${proto} — open it yourself."
    fi
    if command -v ip6tables >/dev/null 2>&1; then
      ip6tables -C INPUT -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null || \
        ip6tables -I INPUT 1 -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null || true
    fi
    persist_iptables
    info "Opened ${colon}/${proto} (iptables)"
  else
    warn "No firewall tool found — open ${dash}/${proto} yourself."
  fi
  warn "Also open ${dash}/${proto} in your provider's security group / cloud firewall."
}

close_port() {
  local port="$1" proto="${2:-tcp}" colon dash
  colon="$(colon_ports "$port")"
  dash="$(dash_ports "$port")"
  if ufw_active; then
    ufw delete allow "${colon}/${proto}" >/dev/null 2>&1 || true
  elif firewalld_active; then
    firewall-cmd --permanent --remove-port="${dash}/${proto}" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  elif command -v iptables >/dev/null 2>&1; then
    iptables -D INPUT -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null || true
    command -v ip6tables >/dev/null 2>&1 && ip6tables -D INPUT -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null || true
    persist_iptables
  fi
}

# ── Who still needs a port ─────────────────────────────────────────────────── #
# close_port used to be called from --uninstall alone, and blindly. So moving a
# server to another port (SS_PORT=8443 bash setup.sh) opened the new one and
# left the old one open for good, and closing a port was only ever safe by
# luck — several protocols can share a number (Reality 443/tcp beside
# Hysteria2 443/udp) or the ACME port 80. Every close now asks first.

# Did this protocol's install open 80/tcp for an ACME http-01 challenge? It is
# recorded as ACME_PORT80 now. State written before that was recorded only the
# domain, and a domain (in TLS mode, for Shadowsocks) is what opened 80.
acme_holds_80() {
  local proto="$1" f="${STATE_DIR}/$1.env" v
  if v=$(ENV_FILE="$f" env_get ACME_PORT80 2>/dev/null); then
    [[ "$v" == "1" ]]; return
  fi
  case "$proto" in
    shadowsocks) [[ "$(ENV_FILE="$f" env_get V2RAY_PLUGIN_MODE 2>/dev/null || true)" == "tls" ]] && \
                   [[ -n "$(ENV_FILE="$f" env_get SS_DOMAIN 2>/dev/null || true)" ]] ;;
    hysteria2)   [[ -n "$(ENV_FILE="$f" env_get HY2_DOMAIN 2>/dev/null || true)" ]] ;;
    tuic)        [[ -n "$(ENV_FILE="$f" env_get TUIC_DOMAIN 2>/dev/null || true)" ]] ;;
    *)           return 1 ;;
  esac
}

# Every "port/transport" a protocol's saved state says it holds open, one per
# line. Hop segments come out in their dash form ("20000-30000/udp").
proto_ports() {
  local proto="$1" f="${STATE_DIR}/$1.env" p r seg
  case "$proto" in
    shadowsocks)
      p=$(ENV_FILE="$f" env_get SS_PORT 2>/dev/null) || p=""
      [[ -n "$p" ]] && echo "${p}/tcp"
      # The 2022 backend relays UDP too; the v2ray-plugin one never opened it.
      [[ -n "$p" && "$(ENV_FILE="$f" env_get SS_BACKEND 2>/dev/null || true)" == "sing-box" ]] && echo "${p}/udp" ;;
    reality)
      p=$(ENV_FILE="$f" env_get REALITY_PORT 2>/dev/null) && echo "${p}/tcp" ;;
    hysteria2)
      p=$(ENV_FILE="$f" env_get HY2_PORT 2>/dev/null) && echo "${p}/udp"
      r=$(ENV_FILE="$f" env_get HY2_PORT_RANGE 2>/dev/null || true)
      for seg in $(printf '%s' "$r" | tr ',' ' '); do echo "${seg}/udp"; done ;;
    tuic)
      p=$(ENV_FILE="$f" env_get TUIC_PORT 2>/dev/null) && echo "${p}/udp" ;;
  esac
  acme_holds_80 "$proto" && echo "80/tcp"
  return 0
}

# True when something other than protocol $3 still needs port $1 over $2 — and
# for 22/tcp, always: this script opens it so you cannot lock yourself out, and
# it is the one port it must never be the one to close.
port_needed_by_others() {
  local port="$1" proto="$2" self="$3" other held
  [[ "$port" == "22" && "$proto" == "tcp" ]] && { echo "ssh"; return 0; }
  while IFS= read -r other; do
    [[ -z "$other" || "$other" == "$self" ]] && continue
    while IFS= read -r held; do
      [[ -n "$held" ]] || continue
      if [[ "$held" == "${port}/${proto}" ]]; then echo "$other"; return 0; fi
      # A single port inside another protocol's hop range is that range's too.
      if [[ "$held" == *-*/"$proto" && "$port" =~ ^[0-9]+$ ]] && port_in_range "$port" "${held%/*}"; then
        echo "$other"; return 0
      fi
    done < <(proto_ports "$other")
  done < <(installed_protocols)
  return 1
}

# Close port $1/$2 on behalf of protocol $3, unless another one still uses it.
close_port_unless_needed() {
  local port="$1" proto="$2" self="$3" who
  [[ -n "$port" ]] || return 0
  if who=$(port_needed_by_others "$port" "$proto" "$self"); then
    info "Leaving ${port}/${proto} open — ${who} still uses it."
    return 0
  fi
  close_port "$port" "$proto"
  info "Closed ${port}/${proto}."
}

# A re-run that moves a protocol to a new port closes the one it left.
close_stale_port() {
  local old="$1" new="$2" proto="$3" self="$4"
  [[ -n "$old" && "$old" != "$new" ]] || return 0
  info "${self} moved from ${old}/${proto} to ${new}/${proto}."
  close_port_unless_needed "$old" "$proto" "$self"
}

# 80/tcp is opened for ACME and has to stay open for renewals. Release it once
# this protocol no longer uses a domain — on a re-run without one, or on
# uninstall — and nothing else installed still does.
release_acme_port() {
  local self="$1"
  acme_holds_80 "$self" || return 0
  close_port_unless_needed 80 tcp "$self"
}

### ── Hysteria2 port hopping ────────────────────────────────────────────────── ###
# Publish a whole UDP range and NAT it back to the one port the server listens
# on. The client rotates across the range, so a block aimed at a single port —
# or a shaper that has decided it dislikes one long-lived UDP flow — no longer
# takes the connection down with it.
#
# Canonicalise a hop range to the dash form config-gen writes: "20000-30000",
# "20000-25000,30000-35000", or a bare port. ':' is accepted as the separator
# and whitespace is ignored, so this takes exactly the set that
# normalizePortRange() in config-gen/lib/configs.js takes.
#
# The two used to disagree: this accepted only a single `a-b` pair, while the
# client side happily accepted and emitted comma-separated lists. So a range set
# in the dashboard as "20000-25000,30000-35000" reached every client, and the
# server installed no NAT rule for any of it — every hop aimed at a port with
# nothing behind it. A one-port "range" is still not hopping, so it is accepted
# and then complained about.
normalize_hop_range() {
  local raw="${1//[[:space:]]/}" part lo hi out=""
  [[ -n "$raw" ]] || return 1
  for part in $(printf '%s' "$raw" | tr ',' ' '); do
    if [[ "$part" =~ ^([0-9]+)[-:]([0-9]+)$ ]]; then
      lo="${BASH_REMATCH[1]}"; hi="${BASH_REMATCH[2]}"
    elif [[ "$part" =~ ^([0-9]+)$ ]]; then
      lo="${BASH_REMATCH[1]}"; hi="$lo"
    else
      return 1
    fi
    (( lo >= 1 && hi <= 65535 && lo <= hi )) || return 1
    if [[ "$lo" == "$hi" ]]; then out+="${out:+,}${lo}"; else out+="${out:+,}${lo}-${hi}"; fi
  done
  [[ -n "$out" ]] || return 1
  printf '%s' "$out"
}

# True when the canonical range is a single port and nothing more.
hop_range_is_one_port() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

# True when a port falls inside a canonical hop range ("a-b,c"). Up here with
# the other range helpers because --uninstall, which runs long before the
# install code below is even defined, asks it whether a port is still in use.
port_in_range() {
  local port="$1" range="$2" seg lo hi
  for seg in $(printf '%s' "$range" | tr ',' ' '); do
    lo="${seg%-*}"; hi="${seg#*-}"
    (( port >= lo && port <= hi )) && return 0
  done
  return 1
}

open_hop_range() {
  local raw="$1" target="$2" canon seg ipt
  [[ -n "$raw" ]] || return 0
  canon=$(normalize_hop_range "$raw") || {
    warn "HY2_PORT_RANGE '${raw}' is not a usable range — write it as 20000-30000 (or a comma-separated list). Ignoring it."
    return 1
  }
  if hop_range_is_one_port "$canon"; then
    warn "HY2_PORT_RANGE '${raw}' is a single port — hopping needs a span like 20000-30000 to be worth anything."
  fi
  command -v iptables >/dev/null 2>&1 || { warn "iptables is missing — cannot set up port hopping."; return 1; }

  # One NAT rule and one firewall opening per comma-separated segment: iptables
  # takes a single range per --dport, so a list has to be walked.
  for seg in $(printf '%s' "$canon" | tr ',' ' '); do
    ipt="$(colon_ports "$seg")"
    # -C first: this script is meant to be re-runnable, and a second identical
    # REDIRECT rule is both useless and confusing to read back.
    if ! iptables -t nat -C PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null; then
      iptables -t nat -A PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null || {
        warn "Could not add the port-hopping NAT rule for ${seg} — hopping will not work."; return 1; }
    fi
    if command -v ip6tables >/dev/null 2>&1; then
      ip6tables -t nat -C PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null || \
        ip6tables -t nat -A PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null || true
    fi
    # open_port speaks each firewall's own dialect; hand it one segment.
    open_port "$seg" udp
  done
  install_hop_unit "$canon" "$target"
  info "Port hopping: UDP ${canon} → ${target}"
  warn "Open the whole ${canon}/udp range in your provider's security group too, or hopping will stall."
  # Hand the canonical form back on stdout so the caller records and advertises
  # exactly what was installed rather than the spelling that was typed. Every
  # diagnostic in this script goes to stderr (see info/warn above), so stdout
  # carries nothing but this.
  printf '%s' "$canon"
  return 0
}

close_hop_range() {
  local raw="$1" target="$2" canon seg ipt
  [[ -n "$raw" ]] || return 0
  canon=$(normalize_hop_range "$raw") || return 0
  command -v iptables >/dev/null 2>&1 || return 0
  for seg in $(printf '%s' "$canon" | tr ',' ' '); do
    ipt="$(colon_ports "$seg")"
    iptables -t nat -D PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null || true
    command -v ip6tables >/dev/null 2>&1 && \
      ip6tables -t nat -D PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null || true
    close_port "$seg" udp
  done
  # close_port only re-saves iptables on the raw-iptables path. Under ufw or
  # firewalld an earlier run may still have left the NAT rules in a saved
  # rules.v4, and a deleted redirect that comes back at boot is still stale.
  if [[ -d /etc/iptables ]] || command -v netfilter-persistent >/dev/null 2>&1; then
    persist_iptables
  fi
  remove_hop_unit
  return 0
}

# ── The Shadowsocks 2022 backend's files ─────────────────────────────────── #
# Declared up here, with the other helpers --uninstall reaches for: it runs
# before the install functions further down are even defined.
SS2022_DIR=/etc/airport-ss2022
SS2022_UNIT=/etc/systemd/system/airport-ss2022.service

stop_ss2022_backend() {
  [[ -f "$SS2022_UNIT" ]] || return 0
  systemctl disable --now airport-ss2022 >/dev/null 2>&1 || true
  rm -f "$SS2022_UNIT"
  rm -rf "$SS2022_DIR"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

# ── Keeping the hop redirect across a reboot ──────────────────────────────── #
# The NAT rule used to be persisted with iptables-persistent, which on a box
# running ufw meant apt removing ufw to install it (the packages conflict). A
# oneshot unit that re-applies the rule at boot works the same under ufw,
# firewalld or bare iptables, and is removed cleanly with the protocol.
HOP_SCRIPT="${STATE_DIR}/hy2-hop.sh"
HOP_UNIT=/etc/systemd/system/airport-hy2-hop.service

install_hop_unit() {
  local canon="$1" target="$2" seg ipt
  mkdir -p "$STATE_DIR"
  {
    echo '#!/usr/bin/env bash'
    echo '# Written by airport-tool setup.sh — re-applies the Hysteria2 port-hopping redirect.'
    for seg in $(printf '%s' "$canon" | tr ',' ' '); do
      ipt="$(colon_ports "$seg")"
      echo "iptables -t nat -C PREROUTING -p udp --dport ${ipt} -j REDIRECT --to-ports ${target} 2>/dev/null || iptables -t nat -A PREROUTING -p udp --dport ${ipt} -j REDIRECT --to-ports ${target}"
      echo "if command -v ip6tables >/dev/null 2>&1; then ip6tables -t nat -C PREROUTING -p udp --dport ${ipt} -j REDIRECT --to-ports ${target} 2>/dev/null || ip6tables -t nat -A PREROUTING -p udp --dport ${ipt} -j REDIRECT --to-ports ${target} 2>/dev/null || true; fi"
    done
    echo 'exit 0'
  } > "$HOP_SCRIPT"
  chmod 700 "$HOP_SCRIPT"
  # After the firewalls, so a ruleset they load at boot cannot land on top.
  cat > "$HOP_UNIT" <<EOF
[Unit]
Description=airport-tool Hysteria2 port-hopping redirect
After=network-pre.target ufw.service firewalld.service netfilter-persistent.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash ${HOP_SCRIPT}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable airport-hy2-hop.service >/dev/null 2>&1 || \
    warn "Could not enable airport-hy2-hop.service — the hop redirect will not survive a reboot."
}

remove_hop_unit() {
  systemctl disable airport-hy2-hop.service >/dev/null 2>&1 || true
  rm -f "$HOP_UNIT" "$HOP_SCRIPT"
  systemctl daemon-reload >/dev/null 2>&1 || true
}

### ── Upstream installers ────────────────────────────────────────────────────── ###
# Download an installer to a file, check it against its pinned hash, and only
# then run it. Never `bash <(curl …)`: piped, a truncated download runs as far
# as it got, and nothing can be checked before the first line executes.
#
#   run_installer NAME PINNED_URL SHA256 MOVING_URL [installer args…]
#
# Returns non-zero (with the reason on stderr) rather than exiting, so that
# --uninstall can carry on with its own cleanup when the download fails.
run_installer() {
  local name="$1" url="$2" sha="$3" latest="$4"; shift 4
  local tmp got rc=0 script
  if [[ "$ALLOW_UNPINNED_INSTALLERS" == "1" ]]; then
    warn "ALLOW_UNPINNED_INSTALLERS=1 — running the ${name} installer from ${latest} without checking it."
    url="$latest"; sha=""
  fi
  tmp=$(mktemp -d)
  script="${tmp}/${name}-install.sh"
  if ! curl -fsSL --retry 3 --max-time 120 "$url" -o "$script"; then
    rm -rf "$tmp"; warn "Could not download the ${name} installer from ${url}"; return 1
  fi
  if [[ -n "$sha" ]]; then
    got=$(sha256sum "$script" | awk '{print $1}')
    if [[ "$got" != "$sha" ]]; then
      rm -rf "$tmp"
      warn "The ${name} installer at ${url} does not match its pinned checksum (got ${got}, want ${sha}) — refusing to run it as root."
      return 1
    fi
  fi
  # Run from its own directory: sing-box's installer drops the package it
  # downloads into the current one, which used to be wherever you ran this.
  # Its chatter goes to a log that is shown only when it fails.
  ( cd "$tmp" && bash "$script" "$@" ) >"${tmp}/log" 2>&1 || rc=$?
  if [[ $rc -ne 0 ]]; then
    warn "The ${name} installer exited ${rc}. Its last lines:"
    tail -n 15 "${tmp}/log" >&2 || true
  fi
  rm -rf "$tmp"
  return $rc
}

# "${a[@]+"${a[@]}"}" because an empty array under `set -u` is an unbound
# variable on the older bash some of the supported releases still ship.
install_xray_core() {
  local a=(install)
  [[ "$XRAY_VERSION" != "latest" ]] && a+=(--version "$XRAY_VERSION")
  run_installer xray "$XRAY_INSTALLER_URL" "$XRAY_INSTALLER_SHA256" "$XRAY_INSTALLER_LATEST" "${a[@]}"
}

install_hysteria() {
  local a=()
  [[ "$HY2_VERSION" != "latest" ]] && a=(--version "$HY2_VERSION")
  run_installer hysteria "$HY2_INSTALLER_URL" "$HY2_INSTALLER_SHA256" "$HY2_INSTALLER_LATEST" ${a[@]+"${a[@]}"}
}

# sing-box serves both TUIC and Shadowsocks 2022.
install_singbox() {
  local a=()
  [[ "$SINGBOX_VERSION" != "latest" ]] && a=(--version "${SINGBOX_VERSION#v}")
  run_installer sing-box "$SINGBOX_INSTALLER_URL" "$SINGBOX_INSTALLER_SHA256" "$SINGBOX_INSTALLER_LATEST" ${a[@]+"${a[@]}"}
}

# ── Which account a service runs as ──────────────────────────────────────── #
# "user group" for a systemd unit. Xray-install has run xray.service as nobody
# and, since 2025, as its own `xray` user — so a config handed to nobody's
# group, the right answer for the first, is one the second cannot open, and
# the service dies on start with a permission error. Ask the unit instead.
unit_account() {
  local unit="$1" u g f
  u=$(systemctl show -p User --value "$unit" 2>/dev/null || true)
  g=$(systemctl show -p Group --value "$unit" 2>/dev/null || true)
  for f in "/etc/systemd/system/${unit}.service" "/lib/systemd/system/${unit}.service" "/usr/lib/systemd/system/${unit}.service"; do
    [[ -f "$f" ]] || continue
    [[ -z "$u" ]] && u=$(sed -n 's/^User=//p' "$f" | tail -1)
    [[ -z "$g" ]] && g=$(sed -n 's/^Group=//p' "$f" | tail -1)
    break
  done
  [[ -z "$u" ]] && u=root
  [[ -z "$g" ]] && g=$(id -gn "$u" 2>/dev/null || echo "$u")
  printf '%s %s' "$u" "$g"
}

# Make a root-owned secret readable by the group unit $2 runs as, and by
# nobody else. Falls back to nobody's group when the unit names none.
service_group_owns() {
  local f="$1" unit="$2" acct grp
  acct=$(unit_account "$unit"); grp="${acct#* }"
  if [[ -n "$grp" && "$grp" != "root" ]] && chown "root:${grp}" "$f" 2>/dev/null; then
    chmod 640 "$f"
  else
    nobody_group_owns "$f"
  fi
}

# ── Post-install sanity check ───────────────────────────────────────────────── #
# Fail loudly here rather than let the user discover it from a client that just
# won't connect. Up here because --upgrade, dispatched before the install code
# is defined, restarts services too.
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

### ── State files ───────────────────────────────────────────────────────────── ###
PROTO_CANON="$(canon_protocol "$PROTOCOL")" || \
  error "Unknown PROTOCOL: $PROTOCOL (use 'shadowsocks', 'reality', 'hysteria2' or 'tuic')"
ENV_FILE="${STATE_DIR}/${PROTO_CANON}.env"
PROFILE_FILE="${STATE_DIR}/${PROTO_CANON}.profile.json"

# Fold a pre-split-state install into the new layout, once. Without this an
# upgrade would look like "nothing is installed" and happily mint new keys.
migrate_legacy_state() {
  [[ -f "$LEGACY_ENV_FILE" ]] || return 0
  local line proto target
  line=$(grep -m1 '^PROTOCOL=' "$LEGACY_ENV_FILE" 2>/dev/null) || line=""
  proto="${line#*=}"; proto="${proto#\'}"; proto="${proto%\'}"
  if [[ -z "$proto" ]] || ! proto=$(canon_protocol "$proto"); then
    warn "${LEGACY_ENV_FILE} names no protocol I recognise — leaving it alone."
    return 0
  fi
  target="${STATE_DIR}/${proto}.env"
  if [[ -f "$target" ]]; then
    rm -f "$LEGACY_ENV_FILE"
    return 0
  fi
  mv "$LEGACY_ENV_FILE" "$target"
  chmod 600 "$target"
  if [[ -f "${STATE_DIR}/profile.json" ]]; then
    cp "${STATE_DIR}/profile.json" "${STATE_DIR}/${proto}.profile.json"
    chmod 600 "${STATE_DIR}/${proto}.profile.json"
  fi
  info "Moved the old shared server.env to ${target} (one state file per protocol now)."
}
# Except under --doctor, which promises to change nothing — it says so instead.
if [[ -d "$STATE_DIR" && $DO_DOCTOR -eq 0 ]]; then
  migrate_legacy_state
elif [[ -f "$LEGACY_ENV_FILE" ]]; then
  warn "${LEGACY_ENV_FILE} is old-style state; --doctor does not migrate it. Any other run will."
fi

### ── Re-run safety ─────────────────────────────────────────────────────────── ###
# A second run used to silently mint new keys, breaking every client already
# carrying the old ones. Reuse what's on disk unless FORCE=1 says otherwise.
EXISTING_PROTOCOL=""
[[ -f "$ENV_FILE" ]] && EXISTING_PROTOCOL="$PROTO_CANON"

REUSE=0

# Restore one setting from server.env unless the caller named it on this run.
# Without this a plain `bash setup.sh` re-run silently reverted the port and SNI
# to their defaults — same keys, different endpoint, every client broken, and
# the firewall rule for the old port left open.
restore() {
  local var="$1" key="${2:-$1}" saved
  case " ${EXPLICIT_VARS} " in *" ${var} "*) return 0 ;; esac
  saved="$(env_get "$key" 2>/dev/null || true)"
  [[ -n "$saved" ]] && printf -v "$var" '%s' "$saved"
  return 0
}

compute_reuse() {
if [[ -n "$EXISTING_PROTOCOL" && "$FORCE" != "1" ]]; then
  REUSE=1
  info "Existing ${PROTO_CANON} setup found — reusing its keys, passwords and settings."
  info "Run with FORCE=1 to generate new secrets (this invalidates every existing client)."
  case "$PROTO_CANON" in
    shadowsocks)
      restore SS_PORT; restore SS_METHOD; restore DOMAIN SS_DOMAIN
      restore V2RAY_PLUGIN_MODE ;;
    reality)
      restore REALITY_PORT; restore REALITY_SNI
      restore REALITY_NETWORK; restore REALITY_PATH ;;
    hysteria2)
      restore HY2_PORT; restore HY2_SNI; restore HY2_OBFS; restore HY2_PORT_RANGE
      restore HY2_MASQUERADE; restore HY2_UP; restore HY2_DOWN
      restore DOMAIN HY2_DOMAIN ;;
    tuic)
      restore TUIC_PORT; restore TUIC_SNI; restore DOMAIN TUIC_DOMAIN ;;
  esac
fi
# Each protocol owns its own state now, so a second one really is installed
# alongside rather than on top of the first. Say which are already here, since
# they may be competing for the same port.
local other others=""
while IFS= read -r other; do
  [[ -z "$other" || "$other" == "$PROTO_CANON" ]] && continue
  others="${others} ${other}"
done < <(installed_protocols)
[[ -n "$others" ]] && info "Also installed on this server:${others} (their settings are untouched)."
return 0
}

#############################################################################
# Uninstall
#############################################################################
do_uninstall() {
  # Which one? An explicit PROTOCOL names it. Otherwise: exactly one installed
  # means there is no ambiguity, and anything else has to be spelled out —
  # defaulting to "shadowsocks" here would quietly rip out the wrong server.
  local proto installed count
  installed=$(installed_protocols)
  count=$(echo "$installed" | grep -c '[a-z]' || true)
  if [[ $PROTOCOL_EXPLICIT -eq 1 ]]; then
    proto="$PROTO_CANON"
  elif [[ "$count" -eq 1 ]]; then
    proto="$(echo "$installed" | tr -d '[:space:]')"
  elif [[ "$count" -eq 0 ]]; then
    warn "Nothing recorded in ${STATE_DIR}; removing leftover state only."
    proto=""
  else
    error "Several protocols are installed ($(echo "$installed" | tr '\n' ' ')). Name one: PROTOCOL=reality bash setup.sh --uninstall"
  fi

  ENV_FILE="${STATE_DIR}/${proto}.env"
  [[ -n "$proto" ]] && info "Uninstalling ${proto}..."
  case "$proto" in
    shadowsocks)
      systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/shadowsocks-libev.service
      rm -rf /etc/shadowsocks-libev
      rm -f /etc/letsencrypt/renewal-hooks/deploy/airport-ss.sh
      rm -f /usr/local/bin/v2ray-plugin
      apt-get remove -y -qq shadowsocks-libev >/dev/null 2>&1 || true
      # A 2022 install ran on sing-box under its own unit, and opened UDP too.
      # The sing-box binary stays: TUIC may be using it.
      if [[ "$(env_get SS_BACKEND || true)" == "sing-box" ]]; then
        stop_ss2022_backend
        close_port_unless_needed "$(env_get SS_PORT || echo "$SS_PORT")" udp shadowsocks
      fi
      close_port_unless_needed "$(env_get SS_PORT || echo "$SS_PORT")" tcp shadowsocks
      # TLS mode opened 80 for certbot, and nothing ever closed it again.
      release_acme_port shadowsocks
      ;;
    reality)
      systemctl disable --now xray >/dev/null 2>&1 || true
      # The same pinned, checksummed installer the install used — this used to
      # fetch raw/main and run whatever it found there, as root, to remove it.
      if ! run_installer xray "$XRAY_INSTALLER_URL" "$XRAY_INSTALLER_SHA256" "$XRAY_INSTALLER_LATEST" remove --purge; then
        warn "Removing Xray by hand instead."
        rm -f /usr/local/bin/xray /etc/systemd/system/xray.service /etc/systemd/system/xray@.service
        rm -rf /usr/local/etc/xray /usr/local/share/xray /etc/systemd/system/xray.service.d /etc/systemd/system/xray@.service.d
      fi
      close_port_unless_needed "$(env_get REALITY_PORT || echo "$REALITY_PORT")" tcp reality
      ;;
    tuic)
      systemctl disable --now sing-box >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/sing-box.service /etc/systemd/system/sing-box@.service
      rm -rf /etc/sing-box
      # Shadowsocks 2022 has its own unit but shares this executable/package.
      if [[ -f "${STATE_DIR}/shadowsocks.env" ]] && \
         [[ "$(ENV_FILE="${STATE_DIR}/shadowsocks.env" env_get SS_BACKEND || true)" == "sing-box" ]]; then
        info "Keeping sing-box for Shadowsocks 2022."
      else
        rm -f /usr/local/bin/sing-box
        apt-get remove -y -qq sing-box >/dev/null 2>&1 || true
      fi
      rm -f /etc/letsencrypt/renewal-hooks/deploy/airport-tuic.sh
      # UDP only: that is all the install opened. Closing the same number over
      # TCP as well used to delete the rule Reality depends on whenever the two
      # shared the default 443 — uninstalling TUIC took Reality offline.
      close_port_unless_needed "$(env_get TUIC_PORT || echo "$TUIC_PORT")" udp tuic
      release_acme_port tuic
      ;;
    hysteria2)
      systemctl disable --now hysteria-server.service >/dev/null 2>&1 || true
      if ! run_installer hysteria "$HY2_INSTALLER_URL" "$HY2_INSTALLER_SHA256" "$HY2_INSTALLER_LATEST" --remove; then
        warn "Removing Hysteria2 by hand instead."
        rm -f /usr/local/bin/hysteria /etc/systemd/system/hysteria-server.service /etc/systemd/system/hysteria-server@.service
      fi
      rm -rf /etc/hysteria
      close_hop_range "$(env_get HY2_PORT_RANGE || true)" "$(env_get HY2_PORT || echo "$HY2_PORT")"
      # UDP only, for the same reason as TUIC above.
      close_port_unless_needed "$(env_get HY2_PORT || echo "$HY2_PORT")" udp hysteria2
      release_acme_port hysteria2
      ;;
    *) ;;
  esac
  systemctl daemon-reload >/dev/null 2>&1 || true
  [[ -n "$proto" ]] && rm -f "${STATE_DIR}/${proto}.env" "${STATE_DIR}/${proto}.profile.json"

  # The kernel tuning and the state directory are shared, so they only go when
  # the last protocol does. Ripping them out from under a still-running server
  # was the whole class of bug this split is meant to end.
  if [[ -z "$(installed_protocols)" ]]; then
    rm -f /etc/sysctl.d/99-airport-tuning.conf
    rm -rf "$STATE_DIR"
    info "Uninstalled. Port 22 and your provider's firewall were left untouched."
  else
    rm -f "${STATE_DIR}/profile.json"
    info "Uninstalled ${proto}. Still installed:$(installed_protocols | tr '\n' ' ')"
  fi
  exit 0
}

#############################################################################
# Show saved details
#############################################################################
# "Print what's installed" and "reinstall it" used to be the same command, which
# is a bad property for a script that can change the endpoint your clients use.
# How long is left on a certificate? The failure it warns about — an expired
# cert that every client silently refuses — is invisible in a list of ports and
# passwords, and it is the one that happens on its own while you do nothing.
cert_status() {
  local file="$1" end
  [[ -f "$file" ]] || return 0
  command -v openssl >/dev/null 2>&1 || return 0
  end=$(openssl x509 -in "$file" -enddate -noout 2>/dev/null | sed 's/^notAfter=//') || return 0
  if ! openssl x509 -in "$file" -checkend 0 >/dev/null 2>&1; then
    printf "%s  ${RED}EXPIRED — clients will refuse it${NC}" "$end"
  elif ! openssl x509 -in "$file" -checkend 1209600 >/dev/null 2>&1; then
    printf "%s  ${YELLOW}(expires within 14 days)${NC}" "$end"
  else
    printf '%s' "$end"
  fi
}

show_one() {
  local proto="$1" envf="${STATE_DIR}/$1.env" uri cert line k v status
  echo ""
  echo -e "${GREEN}  ── ${proto} ────────────────────────────────${NC}"
  # Print every recorded key except the URI, which gets its own line below.
  while IFS= read -r line; do
    [[ "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]] || continue
    k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
    [[ "$k" == *_URI ]] && continue
    v="${v#\'}"; v="${v%\'}"
    printf '  %-22s %s\n' "${k}:" "$v"
  done < "$envf"
  case "$proto" in
    shadowsocks) uri=$(ENV_FILE="$envf" env_get SS_URI      || true); cert=/etc/shadowsocks-libev/cert.pem ;;
    reality)     uri=$(ENV_FILE="$envf" env_get REALITY_URI || true); cert="" ;;
    hysteria2)   uri=$(ENV_FILE="$envf" env_get HY2_URI     || true); cert=/etc/hysteria/server.crt ;;
    tuic)        uri=$(ENV_FILE="$envf" env_get TUIC_URI    || true); cert=/etc/sing-box/server.crt ;;
    *)           uri=""; cert="" ;;
  esac
  if [[ -n "$cert" ]]; then
    status=$(cert_status "$cert")
    [[ -n "$status" ]] && printf '  %-22s %b\n' "Certificate expires:" "$status"
  fi
  [[ -f "${STATE_DIR}/${proto}.profile.json" ]] && \
    printf '  %-22s %s\n' "Importable profile:" "${STATE_DIR}/${proto}.profile.json"
  [[ -n "$uri" ]] && { echo ""; echo "  URI: $uri"; }
}

do_show() {
  local installed proto
  installed=$(installed_protocols)
  [[ -n "$installed" ]] || error "Nothing installed yet — ${STATE_DIR} holds no protocol state."
  while IFS= read -r proto; do
    [[ -n "$proto" ]] && show_one "$proto"
  done <<< "$installed"
  echo ""
  exit 0
}

# The machine-readable half of --show: a JSON array of exactly the client
# profiles the generator imports, and nothing else on stdout. It reuses the
# per-protocol profile.json files rather than re-deriving them, so what comes
# down the pipe is byte-identical to what a copied file would have carried.
#
# Every diagnostic goes to stderr so `… --show --json | node gen.js --add -`
# stays parseable even when something is wrong.
do_show_json() {
  local installed proto f body first=1 found=0
  installed=$(installed_protocols)
  [[ -n "$installed" ]] || error "Nothing installed yet — ${STATE_DIR} holds no protocol state."
  printf '[\n'
  while IFS= read -r proto; do
    [[ -n "$proto" ]] || continue
    f="${STATE_DIR}/${proto}.profile.json"
    if [[ ! -f "$f" ]]; then
      warn "${proto} has state but no ${f} — re-run setup.sh for it to regenerate one."
      continue
    fi
    body=$(cat "$f")
    [[ $first -eq 1 ]] || printf ',\n'
    first=0; found=1
    printf '%s' "$body"
  done <<< "$installed"
  printf '\n]\n'
  [[ $found -eq 1 ]] || error "No importable profile found in ${STATE_DIR}."
  exit 0
}

#############################################################################
# Doctor — is what was installed still working?
#############################################################################
# Everything --show prints is what *should* be true. This checks whether it
# is: the failures people actually hit — a service crash-looping on a config
# it cannot read, a firewall rule a cloud image's reset took away, a hop
# redirect pointing at last month's port, a certificate that quietly lapsed —
# all look exactly like "the details are right" from a list of passwords.
#
# Read-only: every probe here (systemctl is-active, ss, iptables -C/-S,
# ufw status, firewall-cmd --query-port, openssl x509) only looks.
DOCTOR_FAILS=0
doc_ok()   { printf "  ${GREEN}✓${NC} %s\n" "$*"; }
doc_fail() { printf "  ${RED}✗${NC} %s\n" "$*"; DOCTOR_FAILS=$((DOCTOR_FAILS + 1)); }
doc_note() { printf "  ${YELLOW}•${NC} %s\n" "$*"; }

# Is anything listening on port $1 over $2? Column 4 of `ss -ln[tu]` is the
# local address, whatever the family: 0.0.0.0:443, [::]:443, *:443.
port_listening() {
  local port="$1" flag=t
  [[ "$2" == "udp" ]] && flag=u
  ss -ln"$flag" 2>/dev/null | awk -v p=":${port}" '
    NR > 1 && substr($4, length($4) - length(p) + 1) == p { found = 1 }
    END { exit !found }'
}

# Does the firewall this script would have used allow $1/$2? 2 = no tool.
firewall_name() {
  if ufw_active; then echo ufw
  elif firewalld_active; then echo firewalld
  elif command -v iptables >/dev/null 2>&1; then echo iptables
  else echo none; fi
}
firewall_allows() {
  local port="$1" proto="$2" colon dash
  colon="$(colon_ports "$port")"; dash="$(dash_ports "$port")"
  case "$(firewall_name)" in
    ufw)       ufw status 2>/dev/null | grep -qE "^${colon}/${proto}[[:space:]]+(ALLOW|LIMIT)" ;;
    firewalld) firewall-cmd --query-port="${dash}/${proto}" >/dev/null 2>&1 ;;
    iptables)  iptables -C INPUT -p "$proto" --dport "$colon" -j ACCEPT 2>/dev/null ;;
    *)         return 2 ;;
  esac
}

# Whole days left on a certificate (negative once expired).
cert_days_left() {
  local end end_s
  end=$(openssl x509 -in "$1" -enddate -noout 2>/dev/null | sed 's/^notAfter=//')
  [[ -n "$end" ]] || return 1
  end_s=$(date -d "$end" +%s 2>/dev/null) || return 1
  echo $(( (end_s - $(date +%s)) / 86400 ))
}

# Can account $1 read file $2? Asked as that account, so a directory it cannot
# traverse counts too — root's own -r test would always say yes.
user_can_read() {
  local user="$1" f="$2"
  [[ -e "$f" ]] || return 1
  [[ "$user" == "root" ]] && return 0
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$user" -- test -r "$f" 2>/dev/null
  else
    su -s /bin/sh "$user" -c 'test -r "$1"' _ "$f" 2>/dev/null
  fi
}

doc_service() {
  if systemctl is-active --quiet "$1" 2>/dev/null; then doc_ok "service ${1} is active"
  else doc_fail "service ${1} is not active — journalctl -u ${1} -n 30"; fi
}

doc_port() {
  local port="$1" proto="$2" rc=0
  if port_listening "$port" "$proto"; then doc_ok "listening on ${port}/${proto}"
  else doc_fail "nothing is listening on ${port}/${proto}"; fi
  firewall_allows "$port" "$proto" || rc=$?
  case $rc in
    0) doc_ok "firewall ($(firewall_name)) allows ${port}/${proto}" ;;
    2) doc_note "no firewall tool found — check ${port}/${proto} is open yourself" ;;
    *) doc_fail "firewall ($(firewall_name)) has no rule for ${port}/${proto} — re-run setup to restore it" ;;
  esac
}

doc_cert() {
  local f="$1" days
  if [[ ! -f "$f" ]]; then doc_fail "certificate ${f} is missing"; return; fi
  if ! days=$(cert_days_left "$f"); then doc_fail "certificate ${f} cannot be read"; return; fi
  # Under 14 days counts as a failure, not a warning: certbot renews at 30, so
  # a certificate this close to the end means renewal is already broken.
  if (( days < 0 )); then doc_fail "certificate ${f} EXPIRED $(( -days )) day(s) ago — clients will refuse it"
  elif (( days < 14 )); then doc_fail "certificate ${f} expires in ${days} day(s) — renewal is not happening"
  else doc_ok "certificate ${f} valid for ${days} more day(s)"; fi
}

doc_readable() {
  local f="$1" unit="$2" acct user
  acct=$(unit_account "$unit"); user="${acct%% *}"
  if user_can_read "$user" "$f"; then doc_ok "${f} is readable by ${unit}'s user (${user})"
  else doc_fail "${f} is not readable by ${unit}'s user (${user}) — the service cannot load its config"; fi
}

# The hop redirect: one REDIRECT per saved segment to the saved port, and no
# other REDIRECT aimed at that port or into that range — a leftover from an
# earlier run sits ahead of the new rule and wins.
doc_hop() {
  local range="$1" target="$2" seg ipt line dport to want lo
  for seg in $(printf '%s' "$range" | tr ',' ' '); do
    ipt="$(colon_ports "$seg")"
    if iptables -t nat -C PREROUTING -p udp --dport "$ipt" -j REDIRECT --to-ports "$target" 2>/dev/null; then
      doc_ok "hop redirect udp ${seg} → ${target} is in place"
    else
      doc_fail "hop redirect udp ${seg} → ${target} is missing — hopping clients reach nothing"
    fi
    if firewall_allows "$seg" udp; then doc_ok "firewall allows the hop range ${seg}/udp"
    else doc_fail "firewall has no rule for the hop range ${seg}/udp"; fi
  done
  while IFS= read -r line; do
    [[ "$line" == *"-j REDIRECT"* && "$line" == *"-p udp"* ]] || continue
    [[ "$line" =~ --dport\ ([0-9:]+) ]] || continue; dport="${BASH_REMATCH[1]}"
    [[ "$line" =~ --to-ports\ ([0-9]+) ]] || continue; to="${BASH_REMATCH[1]}"
    want=0
    for seg in $(printf '%s' "$range" | tr ',' ' '); do
      [[ "$(colon_ports "$seg")" == "$dport" && "$to" == "$target" ]] && want=1
    done
    [[ $want -eq 1 ]] && continue
    lo="${dport%%:*}"
    if [[ "$to" == "$target" ]] || port_in_range "$lo" "$range"; then
      doc_fail "stale hop redirect udp $(dash_ports "$dport") → ${to} (not the saved ${range} → ${target}) — re-run setup to clear it"
    fi
  done < <(iptables -t nat -S PREROUTING 2>/dev/null || true)
  if systemctl is-enabled --quiet airport-hy2-hop.service 2>/dev/null && [[ -f "$HOP_SCRIPT" ]]; then
    doc_ok "boot unit airport-hy2-hop.service re-applies the redirect"
  else
    doc_fail "airport-hy2-hop.service is not enabled — the redirect will not survive a reboot"
  fi
}

doctor_one() {
  local proto="$1" f="${STATE_DIR}/$1.env" p r d acme_cert
  echo ""
  echo -e "${GREEN}── ${proto}${NC}"
  case "$proto" in
    shadowsocks)
      p=$(ENV_FILE="$f" env_get SS_PORT || true)
      if [[ "$(ENV_FILE="$f" env_get SS_BACKEND || true)" == "sing-box" ]]; then
        doc_service airport-ss2022
        doc_port "$p" tcp; doc_port "$p" udp
        doc_readable "${SS2022_DIR}/config.json" airport-ss2022
      else
        doc_service shadowsocks-libev
        doc_port "$p" tcp
        doc_readable /etc/shadowsocks-libev/config.json shadowsocks-libev
        if [[ "$(ENV_FILE="$f" env_get V2RAY_PLUGIN_MODE || true)" == "tls" ]]; then
          doc_cert /etc/shadowsocks-libev/cert.pem
        fi
      fi ;;
    reality)
      doc_service xray
      doc_port "$(ENV_FILE="$f" env_get REALITY_PORT || true)" tcp
      doc_readable /usr/local/etc/xray/config.json xray ;;
    hysteria2)
      p=$(ENV_FILE="$f" env_get HY2_PORT || true)
      doc_service hysteria-server
      doc_port "$p" udp
      doc_readable /etc/hysteria/config.yaml hysteria-server
      d=$(ENV_FILE="$f" env_get HY2_DOMAIN || true)
      if [[ -z "$d" ]]; then
        doc_cert /etc/hysteria/server.crt
      else
        # Hysteria runs its own ACME client and keeps the result in its
        # working directory; find it rather than assume a layout.
        acme_cert=$(find /var/lib/hysteria /etc/hysteria -name "${d}.crt" 2>/dev/null | head -1 || true)
        if [[ -n "$acme_cert" ]]; then doc_cert "$acme_cert"
        else doc_note "Hysteria2 manages the ACME certificate for ${d} itself; none found on disk to check"; fi
      fi
      r=$(ENV_FILE="$f" env_get HY2_PORT_RANGE || true)
      [[ -n "$r" ]] && doc_hop "$r" "$p" ;;
    tuic)
      doc_service sing-box
      doc_port "$(ENV_FILE="$f" env_get TUIC_PORT || true)" udp
      doc_readable /etc/sing-box/config.json sing-box
      doc_cert /etc/sing-box/server.crt ;;
  esac
  if acme_holds_80 "$proto"; then
    if firewall_allows 80 tcp; then doc_ok "firewall allows 80/tcp (certificate renewals)"
    else doc_fail "firewall has no rule for 80/tcp — certificate renewals will fail"; fi
  fi
  return 0
}

do_doctor() {
  local installed proto
  installed=$(installed_protocols)
  [[ -n "$installed" ]] || error "Nothing installed yet — ${STATE_DIR} holds no protocol state."
  while IFS= read -r proto; do
    [[ -n "$proto" ]] && doctor_one "$proto"
  done <<< "$installed"
  echo ""
  if [[ $DOCTOR_FAILS -eq 0 ]]; then
    echo -e "${GREEN}All checks passed.${NC}"
    exit 0
  fi
  echo -e "${RED}${DOCTOR_FAILS} check(s) failed.${NC}"
  exit 1
}

#############################################################################
# Upgrade — new binaries, same everything else
#############################################################################
# Re-running setup also re-applies the config and the firewall, which is more
# than "update Xray" should ever do. This only re-runs the pinned installers
# (or the *_VERSION ones) with --force, so the same version reinstalls too,
# then restarts. Both installers leave an existing config file alone.
do_upgrade() {
  local installed proto singbox_done=0 units=() u
  installed=$(installed_protocols)
  [[ -n "$installed" ]] || error "Nothing installed yet — ${STATE_DIR} holds no protocol state."
  while IFS= read -r proto; do
    case "$proto" in
      reality)
        info "Upgrading Xray (${XRAY_VERSION})..."
        local a=(install --force)
        [[ "$XRAY_VERSION" != "latest" ]] && a+=(--version "$XRAY_VERSION")
        run_installer xray "$XRAY_INSTALLER_URL" "$XRAY_INSTALLER_SHA256" "$XRAY_INSTALLER_LATEST" "${a[@]}" \
          || error "Xray upgrade failed."
        # Xray-install rewrites xray.service, and has changed the account it
        # runs as before now. Re-point the config's group (ownership only —
        # not a byte of it changes) so the restarted service can still read it.
        [[ -f /usr/local/etc/xray/config.json ]] && service_group_owns /usr/local/etc/xray/config.json xray
        units+=(xray) ;;
      hysteria2)
        info "Upgrading Hysteria2 (${HY2_VERSION})..."
        local h=(--force)
        [[ "$HY2_VERSION" != "latest" ]] && h+=(--version "$HY2_VERSION")
        run_installer hysteria "$HY2_INSTALLER_URL" "$HY2_INSTALLER_SHA256" "$HY2_INSTALLER_LATEST" "${h[@]}" \
          || error "Hysteria2 upgrade failed."
        units+=(hysteria-server) ;;
      tuic|shadowsocks)
        if [[ "$proto" == "shadowsocks" && "$(ENV_FILE="${STATE_DIR}/shadowsocks.env" env_get SS_BACKEND || true)" != "sing-box" ]]; then
          info "shadowsocks-libev comes from apt (apt-get upgrade updates it), and v2ray-plugin is pinned — nothing to do."
          continue
        fi
        # One package serves both; install it once.
        if [[ $singbox_done -eq 0 ]]; then
          info "Upgrading sing-box (${SINGBOX_VERSION})..."
          install_singbox || error "sing-box upgrade failed."
          singbox_done=1
        fi
        if [[ "$proto" == "tuic" ]]; then units+=(sing-box); else units+=(airport-ss2022); fi ;;
    esac
  done <<< "$installed"
  systemctl daemon-reload >/dev/null 2>&1 || true
  for u in ${units[@]+"${units[@]}"}; do
    systemctl restart "$u" || true
    verify_service "$u"
  done
  info "Upgrade done. Keys, configs and firewall rules were not touched."
  exit 0
}

#############################################################################
# Export / import — moving to a new VPS without new client links
#############################################################################
# Everything a re-run needs to recreate the same credentials. The state files
# hold every key and password; the rest are the certificates and keys that
# would otherwise be regenerated, and the configs, for reference.
state_paths() {
  printf '%s\n' "$STATE_DIR" \
    /etc/shadowsocks-libev/config.json /etc/shadowsocks-libev/cert.pem /etc/shadowsocks-libev/key.pem \
    "${SS2022_DIR}/config.json" \
    /usr/local/etc/xray/config.json \
    /etc/hysteria/config.yaml /etc/hysteria/server.crt /etc/hysteria/server.key \
    /etc/sing-box/config.json /etc/sing-box/server.crt /etc/sing-box/server.key
}

do_export_state() {
  local installed out="$EXPORT_FILE" p rel=()
  installed=$(installed_protocols)
  [[ -n "$installed" ]] || error "Nothing installed yet — ${STATE_DIR} holds no protocol state to export."
  # From the state directory, only the state files: hy2-hop.sh is rebuilt by
  # the re-run on the other side, and --import-state refuses to unpack it.
  while IFS= read -r p; do
    if [[ "$p" == "$STATE_DIR" ]]; then
      for p in "$STATE_DIR"/*.env "$STATE_DIR"/*.json; do [[ -f "$p" ]] && rel+=("${p#/}"); done
    elif [[ -e "$p" ]]; then
      rel+=("${p#/}")
    fi
  done < <(state_paths)
  # Created 0600 from the first byte, not chmod'ed after: the tarball holds
  # every private key on this server.
  ( umask 077; tar -czf "$out" -C / "${rel[@]}" ) || error "Could not write ${out}."
  chmod 600 "$out"
  info "Exported $(echo "$installed" | tr '\n' ' ')to ${out}"
  warn "${out} holds every key and password for these proxies — keep it as safe as root on this server."
  info "On the new VPS: sudo bash setup.sh --import-state $(basename "$out")"
  exit 0
}

# The address clients were given, as each protocol recorded it.
proto_server() {
  local key
  case "$1" in
    shadowsocks) key=SS_SERVER ;; reality) key=REALITY_SERVER ;;
    hysteria2) key=HY2_SERVER ;; tuic) key=TUIC_SERVER ;; *) return 1 ;;
  esac
  ENV_FILE="${STATE_DIR}/$1.env" env_get "$key" 2>/dev/null || true
}

# The lines of a state file that make up a protocol's credentials.
proto_identity() {
  local f="$1" keys
  case "$2" in
    shadowsocks) keys='SS_PASSWORD|SS_METHOD' ;;
    reality)     keys='REALITY_UUID|REALITY_PRIVATE_KEY|REALITY_SHORT_ID' ;;
    hysteria2)   keys='HY2_PASSWORD|HY2_OBFS_PASSWORD' ;;
    tuic)        keys='TUIC_UUID|TUIC_PASSWORD' ;;
    *)           return 0 ;;
  esac
  grep -E "^(${keys})=" "$f" 2>/dev/null | sort || true
}

do_import_state() {
  local f="$IMPORT_FILE" stage sd line name a ok p proto imported="" changed="" old new
  local allowed=() unset_args=() v
  [[ -f "$f" ]] || error "No such file: ${f}"
  # Each protocol is re-created by running this script again, which a script
  # read from a pipe (bash <(curl …)) cannot do: it has already been consumed.
  if [[ ! -f "$0" ]]; then
    error "--import-state re-runs this script once per protocol, so it has to be a file: curl -fsSLo setup.sh <url> && sudo bash setup.sh --import-state ${f}"
  fi

  # It is unpacked as root, so only what --export-state writes may come out of
  # it: regular files and directories, at exactly those paths. Under the state
  # directory, only state files — hy2-hop.sh, which a root unit runs at boot,
  # is regenerated by the re-run rather than taken from an archive.
  while IFS= read -r p; do allowed+=("${p#/}"); done < <(state_paths)
  sd="${STATE_DIR#/}"
  tar -tzf "$f" >/dev/null 2>&1 || error "${f} is not a gzip tarball."
  while IFS= read -r line; do
    case "${line:0:1}" in -|d) ;; *) error "${f} holds a link or special file — refusing to unpack it: ${line}" ;; esac
  done < <(tar -tvzf "$f" 2>/dev/null)
  while IFS= read -r name; do
    name="${name%/}"; [[ -n "$name" ]] || continue
    [[ "$name" == /* || "$name" == *..* ]] && error "${f} holds an unsafe path: ${name}"
    ok=0
    for a in "${allowed[@]}"; do
      if [[ "$a" == "$sd" ]]; then
        [[ "$name" == "$sd" || "$name" == "$sd"/*.env || "$name" == "$sd"/*.json ]] && ok=1
      else
        [[ "$name" == "$a" ]] && ok=1
      fi
      # A parent directory of an allowed path is fine as a directory entry.
      [[ "$a" == "$name"/* ]] && ok=1
    done
    [[ $ok -eq 1 ]] || error "${f} holds ${name}, which --export-state never writes — refusing to unpack it."
  done < <(tar -tzf "$f")

  stage=$(mktemp -d)
  tar -xzf "$f" -C "$stage" || { rm -rf "$stage"; error "Could not unpack ${f}."; }
  for p in "$stage/$sd"/*.env; do
    [[ -f "$p" ]] || continue
    proto=$(basename "$p" .env)
    canon_protocol "$proto" >/dev/null 2>&1 && imported="${imported} ${proto}"
  done
  [[ -n "$imported" ]] || { rm -rf "$stage"; error "${f} holds no protocol state."; }

  # Never over a different install by accident: that would replace its keys
  # and strand its clients. The same install again is fine — "same" meaning
  # the same credentials, since the address and URI in the state file are
  # rewritten by every re-run, including the one an import ends with.
  local clash=""
  while IFS= read -r proto; do
    [[ -n "$proto" ]] || continue
    if [[ ! -f "$stage/$sd/${proto}.env" ]] || \
       [[ "$(proto_identity "${STATE_DIR}/${proto}.env" "$proto")" != "$(proto_identity "$stage/$sd/${proto}.env" "$proto")" ]]; then
      clash="${clash} ${proto}"
    fi
  done < <(installed_protocols)
  if [[ -n "$clash" ]]; then
    if [[ $DO_FORCE_IMPORT -ne 1 ]]; then
      rm -rf "$stage"
      error "This server already has a different install of:${clash}. Uninstall it first, or pass --force to replace it with the imported one."
    fi
    # Replaced protocols are uninstalled properly first, so their old ports
    # and hop rules are closed rather than orphaned under the imported state.
    for proto in $clash; do
      case " ${imported} " in *" ${proto} "*)
        warn "--force: uninstalling the existing ${proto} to replace it."
        env PROTOCOL="$proto" bash "$0" --uninstall || warn "Uninstalling the existing ${proto} did not finish cleanly." ;;
      esac
    done
  fi

  while IFS= read -r -d '' p; do
    name="/${p#"$stage"/}"
    mkdir -p "$(dirname "$name")"
    cp -p "$p" "$name"
  done < <(find "$stage" -type f -print0)
  rm -rf "$stage"
  chmod 700 "$STATE_DIR"
  chmod 600 "$STATE_DIR"/* 2>/dev/null || true
  info "Restored state for:${imported}"

  # Settings given on this command line would override the imported ones in
  # the re-run, which is the opposite of an import. SERVER_IP is the exception:
  # it is this server's address, not the old one's.
  for v in $EXPLICIT_VARS; do
    unset_args+=(-u "$v"); warn "Ignoring ${v} — an import re-uses the imported setting."
  done

  warn "This server's IP is probably not the old one's. Clients that connect by IP"
  warn "need the new address; ones that use a domain only need its DNS record moved."
  for proto in $imported; do
    old=$(proto_server "$proto")
    info "Re-creating ${proto} from the imported state..."
    env ${unset_args[@]+"${unset_args[@]}"} FORCE=0 PROTOCOL="$proto" bash "$0" \
      || error "Setup for ${proto} failed. The imported state is in place; fix the above and run: PROTOCOL=${proto} bash $0"
    new=$(proto_server "$proto")
    [[ -n "$old" && "$old" != "$new" ]] && changed="${changed}\n    ${proto}: ${old} → ${new}"
  done
  echo ""
  if [[ -n "$changed" ]]; then
    warn "The server address changed — every client using it must update:$(printf '%b' "$changed")"
    warn "Re-import the new profiles: bash setup.sh --show --json | node gen.js --add -"
  else
    info "Same server address as before — existing clients need no changes."
  fi
  exit 0
}

# These dispatch here rather than at the bottom: bash resolves a function name
# only when the call actually executes, so they have to sit below the
# definitions above. Running them before compute_reuse also keeps `--uninstall`
# and `--show` from first announcing that they're installing something.
[[ $DO_UNINSTALL -eq 1 ]] && do_uninstall
[[ $DO_SHOW -eq 1 && $DO_JSON -eq 1 ]] && do_show_json
[[ $DO_SHOW -eq 1 ]] && do_show
[[ $DO_DOCTOR -eq 1 ]] && do_doctor
[[ $DO_UPGRADE -eq 1 ]] && do_upgrade
[[ -n "$EXPORT_FILE" ]] && do_export_state
[[ -n "$IMPORT_FILE" ]] && do_import_state
compute_reuse

### ── Input validation ──────────────────────────────────────────────────────── ###
# Checked after compute_reuse so saved values are held to the same rules, and
# before anything is installed so a typo costs nothing.
validate_inputs() {
  check_hostname DOMAIN "$DOMAIN"
  if [[ -n "${ACME_EMAIL:-}" && ! "$ACME_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]]; then
    error "ACME_EMAIL=${ACME_EMAIL} is not an email address."
  fi
  case "$PROTO_CANON" in
    shadowsocks)
      check_port SS_PORT "$SS_PORT"
      check_secret SS_PASSWORD "${SS_PASSWORD:-}"
      # shadowsocks-libev has no Shadowsocks 2022 support at all, so a 2022
      # method is served by sing-box instead — which runs no plugin, so the
      # v2ray-plugin settings cannot apply to it.
      case "$SS_METHOD" in
        aes-128-gcm|aes-192-gcm|aes-256-gcm|chacha20-ietf-poly1305|xchacha20-ietf-poly1305)
          case "$V2RAY_PLUGIN_MODE" in
            websocket) ;;
            tls) [[ -n "$DOMAIN" ]] || error "V2RAY_PLUGIN_MODE=tls needs DOMAIN=your.domain — a TLS certificate has to be issued for a name. (It used to fall back to plain WebSocket without saying so.)" ;;
            *) error "V2RAY_PLUGIN_MODE must be websocket or tls (got '${V2RAY_PLUGIN_MODE}')." ;;
          esac ;;
        2022-blake3-aes-128-gcm|2022-blake3-aes-256-gcm|2022-blake3-chacha20-poly1305)
          if [[ "$V2RAY_PLUGIN_MODE" == "tls" ]]; then
            error "SS_METHOD=${SS_METHOD} runs without a plugin, so V2RAY_PLUGIN_MODE=tls cannot apply. Drop it, or use a non-2022 cipher for the v2ray-plugin TLS mode."
          fi
          if [[ -n "${SS_PASSWORD:-}" ]] && ! ss2022_key_ok "$SS_PASSWORD" "$(ss2022_key_len "$SS_METHOD")"; then
            error "SS_PASSWORD is not a ${SS_METHOD} key — it must be base64 of exactly $(ss2022_key_len "$SS_METHOD") bytes: openssl rand -base64 $(ss2022_key_len "$SS_METHOD")"
          fi ;;
        2022-*) error "SS_METHOD=${SS_METHOD} is not a Shadowsocks 2022 cipher (2022-blake3-aes-128-gcm, 2022-blake3-aes-256-gcm, 2022-blake3-chacha20-poly1305)." ;;
        *) error "SS_METHOD=${SS_METHOD} is not an AEAD cipher shadowsocks-libev supports (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, …)." ;;
      esac ;;
    reality)
      check_port REALITY_PORT "$REALITY_PORT"
      check_hostname REALITY_SNI "$REALITY_SNI"
      if [[ -n "$REALITY_PATH" && ! "$REALITY_PATH" =~ ^[A-Za-z0-9._~-]+$ ]]; then
        error "REALITY_PATH=${REALITY_PATH} may only hold letters, digits and . _ ~ -"
      fi ;;
    hysteria2)
      check_port HY2_PORT "$HY2_PORT"
      check_hostname HY2_SNI "$HY2_SNI"
      check_hostname HY2_MASQUERADE "$HY2_MASQUERADE"
      check_secret HY2_PASSWORD "${HY2_PASSWORD:-}"
      check_secret HY2_OBFS_PASSWORD "${HY2_OBFS_PASSWORD:-}" ;;
    tuic)
      check_port TUIC_PORT "$TUIC_PORT"
      check_hostname TUIC_SNI "$TUIC_SNI"
      check_secret TUIC_PASSWORD "${TUIC_PASSWORD:-}"
      if [[ -n "${TUIC_UUID:-}" && ! "$TUIC_UUID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        error "TUIC_UUID=${TUIC_UUID} is not a UUID."
      fi ;;
  esac
  return 0
}
validate_inputs

### ── Port conflicts ────────────────────────────────────────────────────────── ###
# Each protocol owns its state, so several can be installed side by side — and
# with the defaults, Hysteria2 and TUIC both want 443/udp. The second install
# used to go ahead, take the port from the first or fail to bind, and report
# success either way. Refuse instead, naming the variable that fixes it.
#
# "port/transport" a protocol listens on, read from its saved state.
proto_listen() {
  local proto="$1" f="${STATE_DIR}/$1.env" port=""
  case "$proto" in
    shadowsocks) port=$(ENV_FILE="$f" env_get SS_PORT) && printf '%s/tcp' "$port" ;;
    reality)     port=$(ENV_FILE="$f" env_get REALITY_PORT) && printf '%s/tcp' "$port" ;;
    hysteria2)   port=$(ENV_FILE="$f" env_get HY2_PORT) && printf '%s/udp' "$port" ;;
    tuic)        port=$(ENV_FILE="$f" env_get TUIC_PORT) && printf '%s/udp' "$port" ;;
    *) return 1 ;;
  esac
}

check_port_conflicts() {
  local mine var other theirs their_range my_range=""
  case "$PROTO_CANON" in
    shadowsocks) mine="${SS_PORT}/tcp";      var=SS_PORT ;;
    reality)     mine="${REALITY_PORT}/tcp"; var=REALITY_PORT ;;
    hysteria2)   mine="${HY2_PORT}/udp";     var=HY2_PORT
                 [[ -n "$HY2_PORT_RANGE" ]] && my_range=$(normalize_hop_range "$HY2_PORT_RANGE" 2>/dev/null || true) ;;
    tuic)        mine="${TUIC_PORT}/udp";    var=TUIC_PORT ;;
  esac
  while IFS= read -r other; do
    [[ -z "$other" || "$other" == "$PROTO_CANON" ]] && continue
    theirs=$(proto_listen "$other") || continue
    [[ -n "$theirs" ]] || continue
    if [[ "$theirs" == "$mine" ]]; then
      error "${PROTO_CANON} would listen on ${mine}, which the installed ${other} already uses. Pick another port, e.g. ${var}=8443 bash setup.sh"
    fi
    # Hysteria2's hop range is NAT-redirected wholesale, so a UDP port inside
    # it belongs to Hysteria2 whatever else thinks it is listening there.
    if [[ -n "$my_range" && "$theirs" == */udp ]] && port_in_range "${theirs%/udp}" "$my_range"; then
      error "HY2_PORT_RANGE=${my_range} covers ${theirs}, which the installed ${other} uses — the redirect would swallow its traffic."
    fi
    if [[ "$other" == "hysteria2" && "$mine" == */udp ]]; then
      their_range=$(ENV_FILE="${STATE_DIR}/hysteria2.env" env_get HY2_PORT_RANGE 2>/dev/null || true)
      if [[ -n "$their_range" ]] && port_in_range "${mine%/udp}" "$their_range"; then
        error "${mine} is inside the installed Hysteria2 hop range (${their_range}), which redirects it. Pick another port with ${var}=…"
      fi
    fi
  done < <(installed_protocols)
  return 0
}
check_port_conflicts

### ── Environment probe ─────────────────────────────────────────────────────── ###
ARCH=$(uname -m)
OS_ID=$(. /etc/os-release && echo "$ID")
info "OS: $OS_ID | Arch: $ARCH | Protocol: $PROTOCOL"

detect_server_ip() {
  local ip a
  # Whatever the caller set wins — but only if it is an address. It lands in
  # every URI and profile.json this run writes.
  if [[ -n "${SERVER_IP:-}" ]]; then
    valid_ip "$SERVER_IP" || error "SERVER_IP=${SERVER_IP} is not an IPv4 or IPv6 address."
    is_private_ip "$SERVER_IP" && warn "SERVER_IP=${SERVER_IP} is a private address — only clients on the same network can reach it."
    return 0
  fi
  # -f so an error page is a failure rather than an "address", and a second
  # service so one being down or blocked from this network is not fatal. The
  # answer is only taken if it is an address literal of the family asked for:
  # this used to accept anything at all — a captive portal's HTML, a rate-limit
  # message — and write it into the URI of every client.
  if ip=$(probe_ip 4 https://ifconfig.me https://api.ipify.org); then
    SERVER_IP="$ip"; return 0
  fi
  if ip=$(probe_ip 6 https://ifconfig.me https://api6.ipify.org); then
    SERVER_IP="$ip"
    warn "Only an IPv6 address was found — clients on IPv4-only networks won't reach this server."
    return 0
  fi
  # Last resort: an address of this machine's own. On most VPSes that is the
  # public one; behind NAT (and on many cloud images) it is private, and links
  # built from it work for nobody.
  for a in $(hostname -I 2>/dev/null || true); do
    valid_ip "$a" && { ip="$a"; break; }
  done
  [[ -n "${ip:-}" ]] || error "Could not determine this server's public IP. Set it yourself: SERVER_IP=203.0.113.7 bash setup.sh"
  if is_private_ip "$ip"; then
    warn "════════════════════════════════════════════════════════════════════"
    warn "Could not reach an IP-echo service, and this machine's own address,"
    warn "${ip}, is a private one. Client links built from it will not work"
    warn "from the internet. Re-run with the public address set:"
    warn "    SERVER_IP=<public address> bash setup.sh"
    warn "════════════════════════════════════════════════════════════════════"
  else
    warn "Could not reach an IP-echo service — using this machine's own address, ${ip}. Set SERVER_IP=… if that is wrong."
  fi
  SERVER_IP="$ip"
}
detect_server_ip
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

#############################################################################
# Shadowsocks + v2ray-plugin
#############################################################################
# What the previous run of this protocol left open, read before this run
# overwrites the state that records it. FORCE=1 regenerates secrets but the old
# ports are just as open, so this is read whether or not anything is reused.
OLD_PORT=""; OLD_BACKEND=""; OLD_RANGE=""
read_previous_state() {
  case "$PROTO_CANON" in
    shadowsocks) OLD_PORT=$(env_get SS_PORT 2>/dev/null || true)
                 OLD_BACKEND=$(env_get SS_BACKEND 2>/dev/null || true) ;;
    reality)     OLD_PORT=$(env_get REALITY_PORT 2>/dev/null || true) ;;
    hysteria2)   OLD_PORT=$(env_get HY2_PORT 2>/dev/null || true)
                 OLD_RANGE=$(env_get HY2_PORT_RANGE 2>/dev/null || true) ;;
    tuic)        OLD_PORT=$(env_get TUIC_PORT 2>/dev/null || true) ;;
  esac
  return 0
}

# Whether this run opened 80/tcp for ACME; recorded as ACME_PORT80. A re-run
# that drops the domain hands the port back (release_acme_port reads the old
# state, so this is called before the new state is written).
ACME_PORT80=0
finish_acme_port() {
  [[ "$ACME_PORT80" == "1" ]] && return 0
  release_acme_port "$PROTO_CANON"
}

setup_shadowsocks() {
  case "$SS_METHOD" in 2022-*) setup_ss2022; return ;; esac
  # Switching back from a 2022 install: its sing-box would still hold the port.
  stop_ss2022_backend

  # Reuse the existing password so already-distributed clients keep working.
  if [[ $REUSE -eq 1 && -z "${SS_PASSWORD:-}" ]]; then
    SS_PASSWORD="$(env_get SS_PASSWORD || true)"
  fi
  SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 16)}"

  info "Installing shadowsocks-libev..."
  apt-get update -qq
  apt-get install -y -qq shadowsocks-libev

  info "Installing v2ray-plugin..."
  # The release tarballs name their binary with underscores — v2ray-plugin_linux_amd64
  # — and 32-bit ARM ships as one "arm" tarball holding arm5/arm6/arm7 builds.
  # This used to install "v2ray-plugin-linux-amd64", a file no tarball contains,
  # so every Shadowsocks install died at this step; and it asked for an
  # "armv7" tarball that was never published.
  #
  # The checksums are of the published v1.3.2 assets. A download that does not
  # match is refused rather than run as root: this binary sits in front of
  # every connection the server accepts.
  local V2RAY_VER="1.3.2" ARCH_TAG MEMBER SHA
  case "$ARCH" in
    x86_64)        ARCH_TAG="amd64"; MEMBER="v2ray-plugin_linux_amd64"
                   SHA="45856c08a8310b68b8692234eceecfcccb551c607b94a57ce577581decf747a9" ;;
    aarch64|arm64) ARCH_TAG="arm64"; MEMBER="v2ray-plugin_linux_arm64"
                   SHA="d3b6e460f145a0bec27c2dd6490cdaad655d3232ce13bdbfc762c505bdf03d49" ;;
    armv7*)        ARCH_TAG="arm";   MEMBER="v2ray-plugin_linux_arm7"
                   SHA="ce364a7dbab7d853aa2ccd4025e721698dbab198d280488049b68c0f413a9066" ;;
    armv6*)        ARCH_TAG="arm";   MEMBER="v2ray-plugin_linux_arm6"
                   SHA="ce364a7dbab7d853aa2ccd4025e721698dbab198d280488049b68c0f413a9066" ;;
    *)             error "Unsupported architecture: $ARCH" ;;
  esac
  local url="https://github.com/teddysun/v2ray-plugin/releases/download/v${V2RAY_VER}/v2ray-plugin-linux-${ARCH_TAG}-v${V2RAY_VER}.tar.gz"
  local tmp got; tmp=$(mktemp -d)
  # -f: an HTTP error is a failure, not an HTML page saved as the tarball.
  curl -fsSL --retry 3 "$url" -o "$tmp/v2ray-plugin.tar.gz" \
    || { rm -rf "$tmp"; error "Could not download v2ray-plugin from ${url}"; }
  got=$(sha256sum "$tmp/v2ray-plugin.tar.gz" | awk '{print $1}')
  if [[ "$got" != "$SHA" ]]; then
    rm -rf "$tmp"
    error "v2ray-plugin download does not match its published checksum (got ${got}, want ${SHA}) — refusing to install it."
  fi
  tar -xzf "$tmp/v2ray-plugin.tar.gz" -C "$tmp" "$MEMBER" \
    || { rm -rf "$tmp"; error "The v2ray-plugin tarball has no ${MEMBER} in it."; }
  install -m 755 "$tmp/${MEMBER}" /usr/local/bin/v2ray-plugin
  rm -rf "$tmp"
  info "v2ray-plugin: $(v2ray-plugin -version 2>&1 | head -1)"

  # Server-side and client-side plugin opts are built separately: server opts
  # carry `server`/`cert`/`key`, which must never appear in a client URI.
  local SERVER_OPTS CLIENT_OPTS
  if [[ "$V2RAY_PLUGIN_MODE" == "tls" && -n "$DOMAIN" ]]; then
    info "TLS mode: obtaining a Let's Encrypt certificate for $DOMAIN..."
    apt-get install -y -qq certbot
    # 80 only: certbot's standalone http-01 challenge is all that needs it, and
    # it has to stay open for renewals. This used to open 443 as well, which
    # nothing here listens on — ss-server and its plugin take SS_PORT, opened
    # below — so it was a hole in the firewall that no uninstall ever closed.
    open_port 80 tcp; ACME_PORT80=1
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
  # "::" with IPv6 dual-stack accepts IPv4 too. Binding 0.0.0.0 meant an
  # IPv6-only VPS — the case the public-IP probe above explicitly warns about —
  # installed cleanly and then accepted nothing.
  local listen; listen="$(listen_any)"
  cat > /etc/shadowsocks-libev/config.json <<EOF
{
    "server": "${listen}",
    "server_port": ${SS_PORT},
    "password": $(json_str "$SS_PASSWORD"),
    "method": "${SS_METHOD}",
    "plugin": "v2ray-plugin",
    "plugin_opts": "${SERVER_OPTS}",
    "timeout": 300,
    "fast_open": false,
    "mode": "tcp_only"
}
EOF
  # ss-server runs as nobody, and a root-owned 0600 file is one it cannot
  # open — the service started, failed to read its own config and exited.
  # Readable by nobody's group, still closed to everyone else.
  nobody_group_owns /etc/shadowsocks-libev/config.json

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
# ss-server runs as nobody, which may not bind a port below 1024 — and 443,
# the natural choice in TLS mode, is one. This grants that and nothing else.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
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
  close_stale_port "$OLD_PORT" "$SS_PORT" tcp shadowsocks
  # Back from a 2022 install, which relayed UDP: the v2ray-plugin backend does
  # not, so the UDP opening it left behind is closed — on the *old* port, which
  # is the one it was opened on.
  if [[ "$OLD_BACKEND" == "sing-box" ]]; then
    close_port_unless_needed "${OLD_PORT:-$SS_PORT}" udp shadowsocks
  fi
  finish_acme_port
  verify_service shadowsocks-libev

  # Build client URI (strip server-only opts; URL-encode the separators).
  local userinfo plugin_param encoded
  # SIP002 userinfo: web-safe base64 (base64url, no padding) to match config-gen.
  userinfo=$(echo -n "${SS_METHOD}:${SS_PASSWORD}" | base64 -w 0 | tr '+/' '-_' | tr -d '=')
  if [[ -n "$CLIENT_OPTS" ]]; then plugin_param="v2ray-plugin;${CLIENT_OPTS}"; else plugin_param="v2ray-plugin"; fi
  encoded=$(urlencode "$plugin_param")
  SS_URI="ss://${userinfo}@$(uri_host "$SS_HOST"):${SS_PORT}?plugin=${encoded}#Airport"

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
    env_put V2RAY_PLUGIN_MODE "$V2RAY_PLUGIN_MODE"
    env_put SS_DOMAIN "$DOMAIN"
    env_put ACME_PORT80 "$ACME_PORT80"
    env_put SS_URI "$SS_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  # Emit a ready-to-use profile for servers.json / the web UI.
  cat > "$PROFILE_FILE" <<PJEOF
{
  "protocol": "shadowsocks",
  "server": "${SS_HOST}",
  "port": ${SS_PORT},
  "password": $(json_str "$SS_PASSWORD"),
  "method": "${SS_METHOD}",
  "plugin": "v2ray-plugin",
  "plugin_opts": "$( [[ -n "$CLIENT_OPTS" ]] && echo "server;${CLIENT_OPTS}" || echo "server" )",
  "remarks": "Airport SS"
}
PJEOF
  chmod 600 "$PROFILE_FILE"
  cp "$PROFILE_FILE" "${STATE_DIR}/profile.json"
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
# Shadowsocks 2022 (served by sing-box)
#############################################################################
# shadowsocks-libev never implemented the 2022 ciphers, which are the ones with
# replay protection and a fixed-length key. sing-box serves them, is already
# what TUIC uses, and runs here under its own unit and config so the two never
# share a file. No plugin: this is bare Shadowsocks, relaying TCP *and* UDP.

setup_ss2022() {
  local keylen saved
  keylen="$(ss2022_key_len "$SS_METHOD")"
  if [[ $REUSE -eq 1 && -z "${SS_PASSWORD:-}" ]]; then
    saved="$(env_get SS_PASSWORD || true)"
    # A key saved for a different cipher (or a libev passphrase) cannot be
    # reused: it is the wrong length, and every client would be refused.
    if [[ -n "$saved" ]] && ss2022_key_ok "$saved" "$keylen"; then
      SS_PASSWORD="$saved"
    elif [[ -n "$saved" ]]; then
      warn "The saved Shadowsocks password is not a ${SS_METHOD} key — generating a new one. Every existing client needs the new details."
    fi
  fi
  SS_PASSWORD="${SS_PASSWORD:-$(openssl rand -base64 "$keylen")}"

  # A libev install on this port would still be holding it.
  systemctl disable --now shadowsocks-libev >/dev/null 2>&1 || true

  info "Installing sing-box (Shadowsocks 2022 server)..."
  apt-get update -qq
  apt-get install -y -qq curl openssl
  install_singbox || error "sing-box install failed."
  local bin listen
  bin="$(command -v sing-box || echo /usr/bin/sing-box)"
  listen="$(listen_any)"

  info "Writing Shadowsocks 2022 config (${SS_METHOD})..."
  mkdir -p "$SS2022_DIR"
  cat > "${SS2022_DIR}/config.json" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "shadowsocks",
      "tag": "ss-in",
      "listen": "${listen}",
      "listen_port": ${SS_PORT},
      "method": "${SS_METHOD}",
      "password": $(json_str "$SS_PASSWORD")
    }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF
  nobody_group_owns "${SS2022_DIR}/config.json"

  cat > "$SS2022_UNIT" <<EOF
[Unit]
Description=Shadowsocks 2022 (sing-box) — airport-tool
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
ExecStart=${bin} run -c ${SS2022_DIR}/config.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=5
LimitNOFILE=51200

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable airport-ss2022 >/dev/null 2>&1 || true
  systemctl restart airport-ss2022

  # Unlike the v2ray-plugin install, this one relays UDP — so both.
  open_port "$SS_PORT" tcp
  open_port "$SS_PORT" udp
  close_stale_port "$OLD_PORT" "$SS_PORT" tcp shadowsocks
  # Only a previous 2022 install opened UDP; a libev one never did.
  [[ "$OLD_BACKEND" == "sing-box" ]] && close_stale_port "$OLD_PORT" "$SS_PORT" udp shadowsocks
  # No plugin, no TLS mode, no certbot: a TLS-mode install before this one
  # leaves its port 80 to be handed back.
  finish_acme_port
  verify_service airport-ss2022

  # SIP002 for a 2022 key: the userinfo is the plain, percent-encoded
  # method:password, because the key is already base64. configs.js reads it
  # back the same way (a ':' or '%' marks the plain form).
  SS_URI="ss://$(urlencode "${SS_METHOD}:${SS_PASSWORD}")@$(uri_host "$SERVER_IP"):${SS_PORT}#Airport%20SS2022"

  print_result "Shadowsocks 2022" \
    "Server=${SERVER_IP}" "Port=${SS_PORT} (TCP + UDP)" "Key=${SS_PASSWORD}" \
    "Method=${SS_METHOD}" "Plugin=none"
  echo "  URI: $SS_URI"

  {
    env_put PROTOCOL shadowsocks
    env_put SS_BACKEND sing-box
    env_put SS_SERVER "$SERVER_IP"
    env_put SS_PORT "$SS_PORT"
    env_put SS_PASSWORD "$SS_PASSWORD"
    env_put SS_METHOD "$SS_METHOD"
    env_put SS_PLUGIN ''
    env_put ACME_PORT80 0
    env_put SS_URI "$SS_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  cat > "$PROFILE_FILE" <<PJEOF
{
  "protocol": "shadowsocks",
  "server": "${SERVER_IP}",
  "port": ${SS_PORT},
  "password": $(json_str "$SS_PASSWORD"),
  "method": "${SS_METHOD}",
  "plugin": "",
  "remarks": "Airport SS2022"
}
PJEOF
  chmod 600 "$PROFILE_FILE"
  cp "$PROFILE_FILE" "${STATE_DIR}/profile.json"
  chmod 600 "${STATE_DIR}/profile.json"
}

#############################################################################
# VLESS + Reality (Xray-core)
#############################################################################
setup_reality() {
  info "Installing Xray-core..."
  apt-get update -qq
  apt-get install -y -qq curl openssl
  install_xray_core || error "Xray install failed."

  # Reality borrows the target site's TLS handshake, so that site must actually
  # speak TLS 1.3 — otherwise the camouflage fails and the connection stands out.
  if ! echo | timeout 8 openssl s_client -connect "${REALITY_SNI}:443" \
        -servername "${REALITY_SNI}" -tls1_3 >/dev/null 2>&1; then
    warn "${REALITY_SNI} did not complete a TLS 1.3 handshake — it is a poor Reality target."
    warn "Pick a site that supports TLS 1.3 + HTTP/2 (e.g. www.microsoft.com, www.amazon.com)."
  fi

  case "$REALITY_NETWORK" in
    tcp|grpc|xhttp) ;;
    *) error "REALITY_NETWORK must be tcp, grpc or xhttp (got '$REALITY_NETWORK')" ;;
  esac
  # grpc needs a serviceName and xhttp a path; both must match on the client, so
  # generate one rather than shipping a guessable default everybody shares.
  if [[ "$REALITY_NETWORK" != "tcp" && -z "$REALITY_PATH" ]]; then
    REALITY_PATH=$(openssl rand -hex 6)
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
    # Xray has printed this two ways. Up to 2025:
    #   Private key: …        Public key: …
    # and since then:
    #   PrivateKey: …         Password (PublicKey): …        Hash32: …
    # The old parser matched only the first, so on any current Xray every
    # Reality install stopped here. Match the label, not its spelling.
    priv=$(printf '%s\n' "$keypair" | tr -d '\r' \
      | awk -F': *' 'tolower($1) ~ /^private ?key$/ {print $2; exit}')
    pub=$(printf '%s\n' "$keypair" | tr -d '\r' \
      | awk -F': *' 'tolower($1) ~ /^(public ?key|password|password \(public ?key\))$/ {print $2; exit}')
    uuid=$(xray uuid)
    sid=$(openssl rand -hex 8)
    [[ -z "$priv" || -z "$pub" ]] && error "Could not parse the keypair from 'xray x25519'."
  else
    info "Reusing the existing UUID and Reality keypair."
  fi

  # Vision is a raw-TCP flow. Xray refuses it on grpc/xhttp, so the inbound has
  # to drop it exactly the way config-gen drops it from the client profile.
  local flow_json='' stream_extra=''
  case "$REALITY_NETWORK" in
    tcp)
      flow_json=', "flow": "xtls-rprx-vision"'
      ;;
    grpc)
      stream_extra=",
        \"grpcSettings\": { \"serviceName\": \"${REALITY_PATH}\" }"
      ;;
    xhttp)
      stream_extra=",
        \"xhttpSettings\": { \"path\": \"/${REALITY_PATH}\", \"mode\": \"auto\" }"
      ;;
  esac

  info "Writing Xray config (SNI: ${REALITY_SNI}, transport: ${REALITY_NETWORK})..."
  mkdir -p /usr/local/etc/xray
  cat > /usr/local/etc/xray/config.json <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "listen": "::",
      "port": ${REALITY_PORT},
      "protocol": "vless",
      "settings": {
        "clients": [ { "id": "${uuid}"${flow_json} } ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "${REALITY_NETWORK}",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_SNI}:443",
          "xver": 0,
          "serverNames": [ "${REALITY_SNI}" ],
          "privateKey": "${priv}",
          "shortIds": [ "${sid}" ]
        }${stream_extra}
      }
    }
  ],
  "outbounds": [ { "protocol": "freedom" } ]
}
EOF
  # A root-only 0600 file is one xray.service cannot open, and it dies on
  # start. Handing it to nobody's group was right while Xray-install ran it as
  # nobody; the pinned installer runs it as its own `xray` user, which that
  # left locked out just the same. Give it to whichever group the unit uses.
  service_group_owns /usr/local/etc/xray/config.json xray

  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray

  open_port "$REALITY_PORT"
  close_stale_port "$OLD_PORT" "$REALITY_PORT" tcp reality
  verify_service xray

  # Build the vless:// URI. The query has to line up field for field with
  # buildVlessUri() in config-gen/lib/configs.js.
  local q_flow='' q_transport=''
  case "$REALITY_NETWORK" in
    tcp)   q_flow='&flow=xtls-rprx-vision' ;;
    grpc)  q_transport="&serviceName=$(urlencode "$REALITY_PATH")&mode=gun" ;;
    xhttp) q_transport="&path=$(urlencode "/${REALITY_PATH}")&mode=auto" ;;
  esac
  REALITY_URI="vless://${uuid}@$(uri_host "$SERVER_IP"):${REALITY_PORT}?encryption=none${q_flow}&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${pub}&sid=${sid}&type=${REALITY_NETWORK}${q_transport}#Airport%20Reality"

  print_result "VLESS + Reality" \
    "Server=${SERVER_IP}" "Port=${REALITY_PORT}" "UUID=${uuid}" \
    "PublicKey=${pub}" "ShortID=${sid}" "SNI=${REALITY_SNI}" \
    "Transport=${REALITY_NETWORK}${REALITY_PATH:+ (${REALITY_PATH})}"
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
    env_put REALITY_NETWORK "$REALITY_NETWORK"
    env_put REALITY_PATH "$REALITY_PATH"
    env_put REALITY_URI "$REALITY_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  # Split out rather than built inline: a `$( … )` that exits non-zero inside a
  # heredoc is survivable, but it made the JSON unreadable.
  local flow_client='' service_client='' path_client=''
  case "$REALITY_NETWORK" in
    tcp)   flow_client='xtls-rprx-vision' ;;
    grpc)  service_client="$REALITY_PATH" ;;
    xhttp) path_client="/${REALITY_PATH}" ;;
  esac

  cat > "$PROFILE_FILE" <<PJEOF
{
  "protocol": "vless-reality",
  "server": "${SERVER_IP}",
  "port": ${REALITY_PORT},
  "uuid": "${uuid}",
  "publicKey": "${pub}",
  "shortId": "${sid}",
  "sni": "${REALITY_SNI}",
  "flow": "${flow_client}",
  "fingerprint": "chrome",
  "network": "${REALITY_NETWORK}",
  "serviceName": "${service_client}",
  "path": "${path_client}",
  "remarks": "Airport Reality"
}
PJEOF
  chmod 600 "$PROFILE_FILE"
  cp "$PROFILE_FILE" "${STATE_DIR}/profile.json"
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
  install_hysteria || error "Hysteria2 install failed."

  mkdir -p /etc/hysteria
  local tls_block sni insecure
  if [[ -n "$DOMAIN" ]]; then
    info "ACME mode: Hysteria2 will obtain a real certificate for ${DOMAIN}."
    open_port 80 tcp; ACME_PORT80=1   # http-01 challenge, and every renewal
    tls_block="acme:
  domains:
    - ${DOMAIN}
  email: ${ACME_EMAIL:-admin@${DOMAIN}}"
    sni="$DOMAIN"
    insecure="false"
  else
    info "Self-signed certificate mode (CN=${HY2_SNI})."
    if reusable_cert /etc/hysteria/server.crt /etc/hysteria/server.key "$HY2_SNI"; then
      info "Keeping the existing self-signed certificate."
    else
      openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout /etc/hysteria/server.key -out /etc/hysteria/server.crt \
        -subj "/CN=${HY2_SNI}" -days 3650 >/dev/null 2>&1 || error "Could not generate a self-signed certificate."
    fi
    chown hysteria:hysteria /etc/hysteria/server.key /etc/hysteria/server.crt 2>/dev/null || true
    chmod 600 /etc/hysteria/server.key
    tls_block="tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key"
    sni="$HY2_SNI"
    insecure="true"
    warn "Self-signed cert — clients must set insecure/skip-cert-verify. Set DOMAIN=… for a real one."
  fi

  # Brutal needs both halves, and a rate that is not a number is a typo rather
  # than a request. Refusing beats writing a profile whose congestion control
  # silently reverts to the thing the flag exists to avoid.
  local bw_up="" bw_down=""
  for _bw in HY2_UP HY2_DOWN; do
    if [[ -n "${!_bw}" ]] && ! [[ "${!_bw}" =~ ^[0-9]+$ ]]; then
      error "${_bw}=${!_bw} must be a whole number of Mbps."
    fi
  done
  if [[ -n "$HY2_UP" && -z "$HY2_DOWN" ]] || [[ -z "$HY2_UP" && -n "$HY2_DOWN" ]]; then
    error "HY2_UP and HY2_DOWN have to be set together — one alone is not a rate, and Hysteria2 falls back to BBR without both."
  fi
  if [[ -n "$HY2_UP" && "$HY2_UP" != "0" && "$HY2_DOWN" != "0" ]]; then
    bw_up="$HY2_UP"; bw_down="$HY2_DOWN"
    info "Declaring ${bw_up}/${bw_down} Mbps to clients — Brutal congestion control is on."
  else
    warn "No HY2_UP/HY2_DOWN — clients will fall back to BBR instead of Brutal. Set both to your link speed in Mbps."
  fi

  # The masquerade target must not be this server. If it is, the camouflage
  # fetches from a port we are not serving and hands the prober an error.
  local masq="$HY2_MASQUERADE"
  if [[ -z "$masq" ]] || { [[ -n "$DOMAIN" ]] && [[ "$masq" == "$DOMAIN" ]]; }; then
    [[ -n "$masq" ]] && warn "HY2_MASQUERADE=${masq} is this server's own domain — a masquerade pointed at itself serves an error. Using www.bing.com."
    masq="www.bing.com"
  fi
  info "Masquerading as ${masq} for anyone who probes without credentials."

  local obfs_block=""
  if [[ "$HY2_OBFS" == "1" ]]; then
    obfs_block="obfs:
  type: salamander
  salamander:
    password: $(yaml_str "$HY2_OBFS_PASSWORD")"
  else
    HY2_OBFS_PASSWORD=""
  fi

  info "Writing Hysteria2 config..."
  cat > /etc/hysteria/config.yaml <<EOF
listen: :${HY2_PORT}

${tls_block}

auth:
  type: password
  password: $(yaml_str "$HY2_PASSWORD")

${obfs_block}

# Anything that probes the port without valid credentials gets a plausible
# website instead of a protocol error — that's the camouflage. The target is
# deliberately somewhere else on the internet: this used to reuse \$sni, which in
# ACME mode is this server's own domain, so the "plausible website" was a request
# to a TCP port nothing here listens on. A prober got an error, which is exactly
# the thing masquerading exists to avoid.
masquerade:
  type: proxy
  proxy:
    url: https://${masq}/
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

  # The previous run's redirect has to go before this run's goes in. Each rule
  # REDIRECTs a range to one port, and PREROUTING takes the first match — so a
  # re-run with a new HY2_PORT or a new range used to append its rules *behind*
  # the old ones, which kept winning: every hop still landed on the old port,
  # where nothing listens any more. The boot unit and the old range's firewall
  # openings went stale with them. Unchanged range and port: left alone.
  local new_canon=""
  [[ -n "$HY2_PORT_RANGE" ]] && new_canon=$(normalize_hop_range "$HY2_PORT_RANGE" 2>/dev/null || true)
  if [[ -n "$OLD_RANGE" ]] && [[ "$OLD_RANGE" != "$new_canon" || "$OLD_PORT" != "$HY2_PORT" ]]; then
    info "Removing the old port-hopping redirect (UDP ${OLD_RANGE} → ${OLD_PORT:-$HY2_PORT})."
    close_hop_range "$OLD_RANGE" "${OLD_PORT:-$HY2_PORT}"
  fi
  close_stale_port "$OLD_PORT" "$HY2_PORT" udp hysteria2
  finish_acme_port

  # A range that fails to apply must not be advertised to clients, or every one
  # of them dials ports nothing is listening on.
  local hop_installed=""
  if [[ -n "$HY2_PORT_RANGE" ]]; then
    if hop_installed=$(open_hop_range "$HY2_PORT_RANGE" "$HY2_PORT"); then
      # The canonical form that was actually installed, not the spelling that
      # was typed, so the URI and profile.json match the NAT rules exactly.
      HY2_PORT_RANGE="$hop_installed"
    else
      HY2_PORT_RANGE=""
    fi
  fi
  verify_service hysteria-server

  # Build the query piece by piece. Note: a command substitution that exits
  # non-zero aborts the whole assignment under `set -e`, so no inline
  # `$( [[ … ]] && echo … )` here — the empty case would kill the script.
  local auth_enc obfs_q="" insecure_q="" mport_q="" hop_norm="" bw_q=""
  auth_enc=$(urlencode "$HY2_PASSWORD")
  if [[ "$HY2_OBFS" == "1" ]]; then
    obfs_q="&obfs=salamander&obfs-password=$(urlencode "$HY2_OBFS_PASSWORD")"
  fi
  if [[ "$insecure" == "true" ]]; then
    insecure_q="&insecure=1"
  fi
  if [[ -n "$HY2_PORT_RANGE" ]]; then
    # Already canonical (dash form, comma-separated) by the time it gets here —
    # open_hop_range hands back what it installed. Kept as a variable of its own
    # because the URI and profile.json both need it.
    hop_norm="$HY2_PORT_RANGE"
    # hop-interval is a client-side choice; emit config-gen's default so a URI
    # scanned from here and one built from servers.json come out identical.
    mport_q="&mport=${hop_norm}&hop-interval=30"
  fi
  if [[ -n "$bw_up" ]]; then
    bw_q="&up=${bw_up}&upmbps=${bw_up}&down=${bw_down}&downmbps=${bw_down}"
  fi
  HY2_URI="hysteria2://${auth_enc}@$(uri_host "$SERVER_IP"):${HY2_PORT}/?sni=${sni}${insecure_q}${obfs_q}${mport_q}${bw_q}#Airport%20Hysteria2"

  print_result "Hysteria2" \
    "Server=${SERVER_IP}" "Port=${HY2_PORT} (UDP)" "Password=${HY2_PASSWORD}" \
    "SNI=${sni}" "Insecure=${insecure}" "Masquerade=${masq}" \
    "Port hopping=${hop_norm:-off}" \
    "Bandwidth=$( [[ -n "$bw_up" ]] && echo "up ${bw_up} / down ${bw_down} Mbps (Brutal)" || echo "not declared — clients use BBR" )" \
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
    env_put HY2_PORT_RANGE "$HY2_PORT_RANGE"
    env_put HY2_UP "$bw_up"
    env_put HY2_DOWN "$bw_down"
    env_put HY2_MASQUERADE "$masq"
    env_put HY2_DOMAIN "$DOMAIN"
    env_put ACME_PORT80 "$ACME_PORT80"
    env_put HY2_URI "$HY2_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  cat > "$PROFILE_FILE" <<PJEOF
{
  "protocol": "hysteria2",
  "server": "${SERVER_IP}",
  "port": ${HY2_PORT},
  "password": $(json_str "$HY2_PASSWORD"),
  "sni": "${sni}",
  "insecure": ${insecure},
  "obfs": "$( [[ "$HY2_OBFS" == "1" ]] && echo "salamander" )",
  "obfsPassword": $(json_str "$HY2_OBFS_PASSWORD"),
  "ports": "${hop_norm}",
  "up": ${bw_up:-0},
  "down": ${bw_down:-0},
  "remarks": "Airport Hysteria2"
}
PJEOF
  chmod 600 "$PROFILE_FILE"
  cp "$PROFILE_FILE" "${STATE_DIR}/profile.json"
  chmod 600 "${STATE_DIR}/profile.json"
}

#############################################################################
# TUIC v5 (QUIC / UDP, served by sing-box)
#############################################################################
# TUIC gets the same UDP-relaying, loss-tolerant transport as Hysteria2 but
# without Hysteria2's distinctive brute-force congestion behaviour, which some
# ISPs shape on sight. sing-box is used as the server because it already ships a
# TUIC inbound and is a single static binary — no second install path to keep
# working.
setup_tuic() {
  if [[ $REUSE -eq 1 ]]; then
    TUIC_UUID="${TUIC_UUID:-$(env_get TUIC_UUID || true)}"
    TUIC_PASSWORD="${TUIC_PASSWORD:-$(env_get TUIC_PASSWORD || true)}"
  fi
  TUIC_UUID="${TUIC_UUID:-$(gen_uuid)}"
  TUIC_PASSWORD="${TUIC_PASSWORD:-$(openssl rand -base64 18)}"

  info "Installing sing-box (TUIC server)..."
  apt-get update -qq
  apt-get install -y -qq curl openssl
  install_singbox || error "sing-box install failed."

  mkdir -p /etc/sing-box
  local cert key sni insecure
  cert=/etc/sing-box/server.crt
  key=/etc/sing-box/server.key
  if [[ -n "$DOMAIN" ]]; then
    info "ACME mode: obtaining a real certificate for ${DOMAIN}."
    apt-get install -y -qq certbot
    open_port 80 tcp; ACME_PORT80=1
    certbot certonly --standalone --non-interactive --agree-tos \
      --register-unsafely-without-email -d "$DOMAIN" || \
      error "certbot failed — is $DOMAIN pointed at $SERVER_IP and port 80 free?"
    cp "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert"
    cp "/etc/letsencrypt/live/${DOMAIN}/privkey.pem"   "$key"
    # certbot renews in the background; without a deploy hook the copies above
    # go stale and the server serves an expired cert about 90 days from now,
    # long after anyone is still looking at this output.
    install_tuic_renewal_hook "$DOMAIN" "$cert" "$key"
    sni="$DOMAIN"
    insecure="false"
  else
    info "Self-signed certificate mode (CN=${TUIC_SNI})."
    if reusable_cert "$cert" "$key" "$TUIC_SNI"; then
      info "Keeping the existing self-signed certificate."
    else
      openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$key" -out "$cert" -subj "/CN=${TUIC_SNI}" -days 3650 >/dev/null 2>&1 || \
        error "Could not generate a self-signed certificate."
    fi
    sni="$TUIC_SNI"
    insecure="true"
    warn "Self-signed cert — clients must skip verification. Set DOMAIN=… for a real one."
  fi
  chmod 600 "$key"

  info "Writing sing-box config..."
  cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "tuic",
      "tag": "tuic-in",
      "listen": "::",
      "listen_port": ${TUIC_PORT},
      "users": [ { "uuid": "${TUIC_UUID}", "password": $(json_str "$TUIC_PASSWORD") } ],
      "congestion_control": "bbr",
      "auth_timeout": "3s",
      "zero_rtt_handshake": true,
      "tls": {
        "enabled": true,
        "server_name": "${sni}",
        "alpn": [ "h3" ],
        "certificate_path": "${cert}",
        "key_path": "${key}"
      }
    }
  ],
  "outbounds": [ { "type": "direct" } ]
}
EOF
  chmod 600 /etc/sing-box/config.json

  systemctl enable sing-box >/dev/null 2>&1 || true
  systemctl restart sing-box

  # QUIC is UDP; the TCP rule most images already carry does nothing for it.
  open_port "$TUIC_PORT" udp
  close_stale_port "$OLD_PORT" "$TUIC_PORT" udp tuic
  finish_acme_port
  verify_service sing-box

  local uuid_enc pw_enc insecure_q=""
  uuid_enc=$(urlencode "$TUIC_UUID")
  pw_enc=$(urlencode "$TUIC_PASSWORD")
  if [[ "$insecure" == "true" ]]; then
    insecure_q="&allow_insecure=1"
  fi
  TUIC_URI="tuic://${uuid_enc}:${pw_enc}@$(uri_host "$SERVER_IP"):${TUIC_PORT}?sni=${sni}&congestion_control=bbr&udp_relay_mode=native&alpn=h3${insecure_q}#Airport%20TUIC"

  print_result "TUIC v5" \
    "Server=${SERVER_IP}" "Port=${TUIC_PORT} (UDP)" "UUID=${TUIC_UUID}" \
    "Password=${TUIC_PASSWORD}" "SNI=${sni}" "Insecure=${insecure}"
  echo "  URI: $TUIC_URI"

  {
    env_put PROTOCOL tuic
    env_put TUIC_SERVER "$SERVER_IP"
    env_put TUIC_PORT "$TUIC_PORT"
    env_put TUIC_UUID "$TUIC_UUID"
    env_put TUIC_PASSWORD "$TUIC_PASSWORD"
    env_put TUIC_SNI "$sni"
    env_put TUIC_INSECURE "$insecure"
    env_put TUIC_DOMAIN "$DOMAIN"
    env_put ACME_PORT80 "$ACME_PORT80"
    env_put TUIC_URI "$TUIC_URI"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  cat > "$PROFILE_FILE" <<PJEOF
{
  "protocol": "tuic",
  "server": "${SERVER_IP}",
  "port": ${TUIC_PORT},
  "uuid": "${TUIC_UUID}",
  "password": $(json_str "$TUIC_PASSWORD"),
  "sni": "${sni}",
  "insecure": ${insecure},
  "congestion": "bbr",
  "udpRelayMode": "native",
  "alpn": "h3",
  "remarks": "Airport TUIC"
}
PJEOF
  chmod 600 "$PROFILE_FILE"
  cp "$PROFILE_FILE" "${STATE_DIR}/profile.json"
  chmod 600 "${STATE_DIR}/profile.json"
}

# Keep sing-box's copy of the certificate in step with certbot's renewals.
install_tuic_renewal_hook() {
  local domain="$1" cert="$2" key="$3"
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/airport-tuic.sh <<HOOK
#!/usr/bin/env bash
cp "/etc/letsencrypt/live/${domain}/fullchain.pem" "${cert}"
cp "/etc/letsencrypt/live/${domain}/privkey.pem"   "${key}"
chmod 600 "${key}"
systemctl restart sing-box
HOOK
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/airport-tuic.sh
  info "Installed a certbot renewal hook so sing-box picks up renewed certificates."
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

# ── Keeping a self-signed certificate ─────────────────────────────────────── #
# Every re-run used to mint a new self-signed certificate, so a client that
# pinned the old one (pinSHA256, or a fingerprint) broke on a run that was
# meant to change nothing — and an --import-state restored a certificate only
# for the re-run to throw it away. Keep it while it still names the same host
# and has more than 30 days left; FORCE=1 replaces it along with the secrets.
reusable_cert() {
  local cert="$1" key="$2" cn="$3"
  [[ $REUSE -eq 1 && -s "$cert" && -s "$key" ]] || return 1
  openssl x509 -in "$cert" -noout -subject 2>/dev/null | grep -qE "CN ?= ?${cn//./\\.}\$" || return 1
  openssl x509 -in "$cert" -noout -checkend 2592000 >/dev/null 2>&1
}

# ── Dispatch ────────────────────────────────────────────────────────────────── #
read_previous_state
open_port 22   # never lock yourself out
enable_bbr

case "$PROTO_CANON" in
  shadowsocks) setup_shadowsocks ;;
  reality)     setup_reality ;;
  hysteria2)   setup_hysteria2 ;;
  tuic)        setup_tuic ;;
  *)           error "Unknown PROTOCOL: $PROTOCOL (use 'shadowsocks', 'reality', 'hysteria2' or 'tuic')" ;;
esac

echo -e "${GREEN}  Config + client profile saved to ${STATE_DIR}/${NC}"
echo -e "${YELLOW}  A ready-to-import profile is at ${PROFILE_FILE}${NC}"
echo -e "${YELLOW}  (also copied to ${STATE_DIR}/profile.json, the most recent install)${NC}"
echo -e "${YELLOW}  Import it on your PC with:  node gen.js --add /path/to/profile.json${NC}"
echo -e "${YELLOW}  (or paste it into the web UI's Import box)${NC}"
echo ""
