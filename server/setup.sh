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
#   XRAY_VERSION      Xray release to install      (default: pinned, see below)
#   HY2_VERSION       Hysteria2 release to install (default: pinned)
#   SINGBOX_VERSION   sing-box release to install  (default: pinned)
#                     Each installer used to fetch whatever was newest, so the
#                     same script installed different software from one week to
#                     the next. Set one to "latest" to opt back into that.
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

# The releases this script was tested against. The v2ray-plugin download below
# has always been pinned and checksummed; the three installers piped into a
# root shell were not, and installed whatever upstream had published that day.
XRAY_VERSION="${XRAY_VERSION:-v26.3.27}"
HY2_VERSION="${HY2_VERSION:-v2.12.3}"
SINGBOX_VERSION="${SINGBOX_VERSION:-1.14.2}"
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
for arg in "$@"; do
  case "$arg" in
    --uninstall) DO_UNINSTALL=1 ;;
    --show)      DO_SHOW=1 ;;
    --json)      DO_JSON=1 ;;
    --help|-h)   usage ;;
    *)           error "Unknown argument: $arg (try --help)" ;;
  esac
done
# --json only means anything alongside --show. Silently ignoring it on an
# install run would be a good way to pipe an installer's chatter into a parser.
[[ $DO_JSON -eq 1 && $DO_SHOW -eq 0 ]] && error "--json only applies to --show (try: bash setup.sh --show --json)"

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
[[ -d "$STATE_DIR" ]] && migrate_legacy_state

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
        close_port "$(env_get SS_PORT || echo "$SS_PORT")" udp
      fi
      close_port "$(env_get SS_PORT || echo "$SS_PORT")" tcp
      ;;
    reality)
      systemctl disable --now xray >/dev/null 2>&1 || true
      bash -c "$(curl -sL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge >/dev/null 2>&1 || true
      close_port "$(env_get REALITY_PORT || echo "$REALITY_PORT")" tcp
      ;;
    tuic)
      systemctl disable --now sing-box >/dev/null 2>&1 || true
      rm -f /etc/systemd/system/sing-box.service /etc/systemd/system/sing-box@.service
      rm -rf /etc/sing-box /usr/local/bin/sing-box
      apt-get remove -y -qq sing-box >/dev/null 2>&1 || true
      rm -f /etc/letsencrypt/renewal-hooks/deploy/airport-tuic.sh
      # UDP only: that is all the install opened. Closing the same number over
      # TCP as well used to delete the rule Reality depends on whenever the two
      # shared the default 443 — uninstalling TUIC took Reality offline.
      close_port "$(env_get TUIC_PORT || echo "$TUIC_PORT")" udp
      ;;
    hysteria2)
      systemctl disable --now hysteria-server.service >/dev/null 2>&1 || true
      bash <(curl -fsSL https://get.hy2.sh/) --remove >/dev/null 2>&1 || true
      rm -rf /etc/hysteria
      close_hop_range "$(env_get HY2_PORT_RANGE || true)" "$(env_get HY2_PORT || echo "$HY2_PORT")"
      # UDP only, for the same reason as TUIC above.
      close_port "$(env_get HY2_PORT || echo "$HY2_PORT")" udp
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

# These dispatch here rather than at the bottom: bash resolves a function name
# only when the call actually executes, so they have to sit below the
# definitions above. Running them before compute_reuse also keeps `--uninstall`
# and `--show` from first announcing that they're installing something.
[[ $DO_UNINSTALL -eq 1 ]] && do_uninstall
[[ $DO_SHOW -eq 1 && $DO_JSON -eq 1 ]] && do_show_json
[[ $DO_SHOW -eq 1 ]] && do_show
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

# True when a port falls inside a canonical hop range ("a-b,c").
port_in_range() {
  local port="$1" range="$2" seg lo hi
  for seg in $(printf '%s' "$range" | tr ',' ' '); do
    lo="${seg%-*}"; hi="${seg#*-}"
    (( port >= lo && port <= hi )) && return 0
  done
  return 1
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

# sing-box from its own installer, at the pinned release. Shared by TUIC.
install_singbox() {
  local args=()
  [[ "$SINGBOX_VERSION" != "latest" ]] && args=(--version "${SINGBOX_VERSION#v}")
  bash <(curl -fsSL https://sing-box.app/install.sh) "${args[@]}" >/dev/null 2>&1 || \
    error "sing-box install failed."
}

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
  install_singbox
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
  local xray_args=(install)
  [[ "$XRAY_VERSION" != "latest" ]] && xray_args+=(--version "$XRAY_VERSION")
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ "${xray_args[@]}" >/dev/null \
    || error "Xray install failed."

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
  chmod 600 /usr/local/etc/xray/config.json

  systemctl enable xray >/dev/null 2>&1 || true
  systemctl restart xray

  open_port "$REALITY_PORT"
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
  local hy2_args=()
  [[ "$HY2_VERSION" != "latest" ]] && hy2_args=(--version "$HY2_VERSION")
  bash <(curl -fsSL https://get.hy2.sh/) "${hy2_args[@]}" >/dev/null 2>&1 || error "Hysteria2 install failed."

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
  install_singbox

  mkdir -p /etc/sing-box
  local cert key sni insecure
  cert=/etc/sing-box/server.crt
  key=/etc/sing-box/server.key
  if [[ -n "$DOMAIN" ]]; then
    info "ACME mode: obtaining a real certificate for ${DOMAIN}."
    apt-get install -y -qq certbot
    open_port 80 tcp
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
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
      -keyout "$key" -out "$cert" -subj "/CN=${TUIC_SNI}" -days 3650 >/dev/null 2>&1 || \
      error "Could not generate a self-signed certificate."
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
