#!/usr/bin/env bash
# Install the dashboard as a systemd service, filled in for this machine.
#
# The health monitor only runs while the dashboard process does. Started from a
# terminal it dies with the terminal, which means the one feature whose whole
# job is to notice an outage while you are not looking stops the moment you stop
# looking. This wires it into systemd instead.
#
#   sudo bash web-ui/install-service.sh              # install (or reinstall) and start
#   sudo bash web-ui/install-service.sh --uninstall  # remove it again
#   sudo bash web-ui/install-service.sh --allow-root # see "Never root" below
#
# Everything it needs is derived from where this script lives and who owns the
# checkout, so there is nothing to edit first.
#
# ── Your settings live in /etc/airport-ui.env ──────────────────────────────── #
# The unit file is regenerated from the template on every run, which used to
# throw away whatever Environment= lines you had added to it — UI_TOKEN,
# TLS_SELFSIGNED, HOST, BACKUP_KEY, CFG_PATH — so a reinstall after `git pull`
# quietly put the dashboard back on loopback with a new token, or pointed it at
# an empty store. Settings now go in an EnvironmentFile instead:
#
#   * it is created once and never overwritten, so a reinstall cannot lose it;
#   * it is 0600 root — systemd reads it before dropping privileges — where the
#     unit file is 0644 and readable by every account on the machine, which is
#     the wrong home for UI_TOKEN and BACKUP_KEY;
#   * on reinstall, any Environment= line you had added to the old unit (one
#     that differs from the template's defaults) is carried into it, once, for
#     any variable it does not already set. EnvironmentFile= lines you added
#     that point elsewhere are kept in the new unit as they were.
#
# ── Writable paths ─────────────────────────────────────────────────────────── #
# ProtectSystem=strict makes the whole filesystem read-only to the service
# except what ReadWritePaths= names. The store, its snapshots, its backup key,
# the probe history and the monitor state all have to be writable, so every
# directory they live in is added: config-gen/ by default, plus the directory of
# CFG_PATH, HISTORY_PATH and MONITOR_STATE_PATH when the env file sets them.
# Change one of those later and re-run this script, or the service hits EROFS
# (the dashboard says so at boot, naming ReadWritePaths).

set -euo pipefail

UNIT_NAME=airport-ui
UNIT_PATH="${UNIT_PATH:-/etc/systemd/system/${UNIT_NAME}.service}"
ENV_FILE="${ENV_FILE:-/etc/${UNIT_NAME}.env}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${HERE}/${UNIT_NAME}.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Escaping ───────────────────────────────────────────────────────────────── #
# Two layers stand between a path and the unit file. sed treats `\`, `&` and
# its delimiter as special in a replacement, so a checkout under a directory
# with `&` in its name came out with the matched placeholder spliced into the
# middle of the path. And systemd expands `%` specifiers, so a literal `%` has
# to be written `%%`. Characters neither layer can carry safely are refused
# rather than guessed at.
unit_safe() {
  local what="$1" value="$2"
  [[ "$value" == *$'\n'* || "$value" == *'"'* || "$value" == *'\'* ]] \
    && error "${what} (${value}) contains a newline, a double quote or a backslash, which a systemd unit cannot carry safely. Move it somewhere plainer."
  return 0
}

unit_escape() { printf '%s' "${1//%/%%}"; }

sed_escape() { printf '%s' "$1" | sed -e 's/[\\&|]/\\&/g'; }

# Substitute one placeholder throughout stdin with a value escaped for both
# layers above. `|` is the delimiter, and sed_escape escapes it too.
subst() { sed -e "s|$1|$(sed_escape "$(unit_escape "$2")")|g"; }

# ── Reading Environment= assignments ───────────────────────────────────────── #
# One Environment= line may hold several assignments, each optionally wrapped in
# double quotes: Environment=A=1 "B=two words". Print one KEY=VALUE per line.
split_assignments() {
  local rest="$1" re_q='^"([^"]*)"[[:space:]]*(.*)$' re_w='^([^[:space:]]+)[[:space:]]*(.*)$'
  while [[ -n "$rest" ]]; do
    if [[ "$rest" =~ $re_q ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"; rest="${BASH_REMATCH[2]}"
    elif [[ "$rest" =~ $re_w ]]; then
      printf '%s\n' "${BASH_REMATCH[1]}"; rest="${BASH_REMATCH[2]}"
    else
      break
    fi
  done
}

# The template's own defaults, which are not "your settings" and must not be
# frozen into the env file (or a changed default would never reach you).
template_assignments() {
  local line
  while IFS= read -r line; do
    if [[ "$line" =~ ^Environment=(.*)$ ]]; then split_assignments "${BASH_REMATCH[1]}"; fi
  done < "$1"
  return 0
}

# Value of KEY in an env file (last one wins, as for systemd), quotes removed.
env_value() {
  local file="$1" key="$2" line val=""
  [[ -f "$file" ]] || return 0
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    [[ "$line" == "${key}="* ]] || continue
    val="${line#*=}"
    if [[ "$val" =~ ^\"(.*)\"$ || "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
  done < "$file"
  printf '%s' "$val"
}

env_has() { [[ -f "$1" ]] && grep -Eq "^[[:space:]]*$2=" "$1"; }

# Create the env file once, with the examples that used to be comments in the
# unit. Never rewritten after that.
create_env_file() {
  local file="$1"
  [[ -f "$file" ]] && return 0
  ( umask 077; cat > "$file" <<'EOF'
# Settings for the airport-ui service. One KEY=VALUE per line; # starts a
# comment. Created once by install-service.sh and never overwritten by it, so
# what you put here survives a reinstall. Apply a change with:
#   sudo systemctl restart airport-ui
# After changing CFG_PATH, HISTORY_PATH or MONITOR_STATE_PATH, re-run
# install-service.sh instead, so the service is allowed to write there.
#
# Values here override the defaults in the unit (HOST=127.0.0.1, PORT=3000).
#
# Bind beyond loopback only on purpose: HOST=0.0.0.0 exposes the dashboard to
# your whole LAN, at which point UI_TOKEN and TLS stop being optional.
#HOST=0.0.0.0
#
# Pin the dashboard token (at least 16 characters). Generate one with:
#   node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))"
#UI_TOKEN=replace-this-with-a-long-random-string
#
# Off loopback, encrypt the LAN hop.
#TLS_SELFSIGNED=1
#
# Point at a sing-box binary to enable the deep connection test.
#SINGBOX_BIN=/usr/local/bin/sing-box
#
# Optional base64-encoded 32-byte snapshot key; share it with CLI writers.
#BACKUP_KEY=your-base64-key
#
# Keep the store somewhere other than config-gen/ (re-run install-service.sh).
#CFG_PATH=/var/lib/airport/servers.json
EOF
  )
  chmod 600 "$file"
}

# Carry custom Environment= lines from an installed unit into the env file —
# only ones that differ from the template's defaults, and only for variables
# the env file does not already set. Prints how many were carried.
migrate_unit_env() {
  local old_unit="$1" template="$2" file="$3" line kv key n=0
  [[ -f "$old_unit" ]] || { echo 0; return 0; }
  local defaults; defaults="$(template_assignments "$template")"
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*Environment=(.*)$ ]] || continue
    while IFS= read -r kv; do
      [[ "$kv" == *=* ]] || continue
      grep -qxF -- "$kv" <<<"$defaults" && continue
      key="${kv%%=*}"
      [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
      env_has "$file" "$key" && continue
      if [[ $n -eq 0 ]]; then
        printf '\n# Carried over from the Environment= lines of the previously installed unit.\n' >> "$file"
      fi
      printf '%s\n' "$kv" >> "$file"
      n=$((n + 1))
    done < <(split_assignments "${BASH_REMATCH[1]}")
  done < "$old_unit"
  echo "$n"
}

# EnvironmentFile= lines you added to the old unit that point somewhere else.
extra_env_files() {
  local old_unit="$1" own="$2" line
  [[ -f "$old_unit" ]] || return 0
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*EnvironmentFile=(.*)$ ]] || continue
    local target="${BASH_REMATCH[1]}"
    [[ "${target#-}" == "$own" ]] && continue
    printf '%s\n' "$line"
  done < "$old_unit"
}

# Absolute path of a configured file, resolved against the service's
# WorkingDirectory the way node will resolve it.
resolve_path() {
  local p="$1" base="$2"
  [[ "$p" == /* ]] && printf '%s' "$p" || printf '%s' "${base%/}/${p}"
}

# Every directory the service has to be able to write: config-gen/ (the
# default store), plus the directory of each of CFG_PATH, HISTORY_PATH and
# MONITOR_STATE_PATH the env file sets. One per line, no duplicates.
writable_dirs() {
  local file="$1" here="$2" default_dir="$3" var val
  {
    printf '%s\n' "$default_dir"
    for var in CFG_PATH HISTORY_PATH MONITOR_STATE_PATH; do
      val="$(env_value "$file" "$var")"
      [[ -n "$val" ]] || continue
      dirname -- "$(resolve_path "$val" "$here")"
    done
  } | awk '!seen[$0]++'
}

# ReadWritePaths= value: each directory quoted, so one with a space in it stays
# one path.
rw_paths_value() {
  local d out=""
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    unit_safe "A writable directory" "$d"
    out+="${out:+ }\"${d}\""
  done
  printf '%s' "$out"
}

render_unit() {
  local template="$1" owner="$2" group="$3" here="$4" node="$5" rw="$6" extras="$7"
  # rw is already quoted; only % needs doubling (unit_escape, inside subst).
  subst REPLACE_USER "$owner" < "$template" \
    | subst REPLACE_GROUP "$group" \
    | subst REPLACE_DIR "$here" \
    | subst REPLACE_NODE "$node" \
    | subst REPLACE_RWPATHS "$rw" \
    | EXTRAS="$extras" awk '{ print } /^EnvironmentFile=/ && !done && ENVIRON["EXTRAS"] != "" { print ENVIRON["EXTRAS"]; done = 1 }'
  # (ENVIRON rather than awk -v, which would interpret backslashes in them.)
}

main() {
  local allow_root="${AIRPORT_ALLOW_ROOT:-}" uninstall=""
  for arg in "$@"; do
    case "$arg" in
      --uninstall) uninstall=1 ;;
      --allow-root) allow_root=1 ;;
      -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}"; exit 0 ;;
      *) error "Unknown option ${arg}. Use --uninstall or --allow-root." ;;
    esac
  done

  [[ $EUID -ne 0 ]] && error "Run as root (sudo bash install-service.sh)"
  command -v systemctl >/dev/null 2>&1 || error "systemd is not available on this machine."

  if [[ -n "$uninstall" ]]; then
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
    info "Removed ${UNIT_NAME}. servers.json, your profiles and ${ENV_FILE} were left alone."
    exit 0
  fi

  [[ -f "$TEMPLATE" ]] || error "Cannot find ${TEMPLATE}"
  [[ -f "${HERE}/server.js" ]] || error "Cannot find ${HERE}/server.js — run this from inside the repo."
  [[ -d "${HERE}/node_modules" ]] || error "Dependencies are missing. Run 'npm install' in ${HERE} first."

  local NODE_BIN; NODE_BIN="$(command -v node)" || error "node is not on PATH."
  [[ "$NODE_BIN" =~ [[:space:]] ]] && error "node lives at a path with a space in it (${NODE_BIN}); ExecStart cannot take that unquoted. Symlink it somewhere plainer."

  # Run as whoever owns the checkout, not as root: this process reads and
  # rewrites a file full of proxy credentials and needs no privilege beyond
  # that file. The unit says "Never root", and installing a root service from
  # a root-owned checkout used to be a warning nobody reads while it scrolls.
  local OWNER GROUP
  OWNER="$(stat -c '%U' "${HERE}/server.js")"
  GROUP="$(stat -c '%G' "${HERE}/server.js")"
  if [[ "$OWNER" == "root" && -z "$allow_root" ]]; then
    echo "" >&2
    echo -e "${RED}[ERROR]${NC} This checkout is owned by root, so the service would run as root." >&2
    echo "        It reads and rewrites a file full of proxy credentials and needs no" >&2
    echo "        privilege beyond that file. Hand the checkout to a normal account:" >&2
    echo "" >&2
    echo "          sudo chown -R youruser:youruser $(dirname "$HERE")" >&2
    echo "          sudo bash ${HERE}/install-service.sh" >&2
    echo "" >&2
    echo "        Or, if root really is what you want: --allow-root (or AIRPORT_ALLOW_ROOT=1)." >&2
    exit 1
  fi
  [[ "$OWNER" == "root" ]] && warn "Installing a service that runs as root, because you asked to (--allow-root)."
  for v in "$OWNER" "$GROUP"; do
    [[ "$v" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*\$?$ ]] || error "Owner/group name '${v}' is not one systemd accepts."
  done
  unit_safe "The checkout path" "$HERE"

  # servers.json lives beside the CLI generator by default.
  local STATE_DIR; STATE_DIR="$(cd "${HERE}/../config-gen" && pwd)"

  # Settings first: created once, then topped up from the old unit.
  local fresh=""; [[ -f "$ENV_FILE" ]] || fresh=1
  create_env_file "$ENV_FILE"
  [[ -n "$fresh" ]] && info "Created ${ENV_FILE} (0600) — your settings go there, not in the unit."
  local carried; carried="$(migrate_unit_env "$UNIT_PATH" "$TEMPLATE" "$ENV_FILE")"
  [[ "$carried" -gt 0 ]] && info "Carried ${carried} setting(s) from the old unit's Environment= lines into ${ENV_FILE}."
  local extras; extras="$(extra_env_files "$UNIT_PATH" "$ENV_FILE")"
  [[ -n "$extras" ]] && info "Keeping your other EnvironmentFile= line(s) from the old unit."

  # Directories the service must write — created (owned by the service user)
  # if missing, because systemd refuses to start a unit whose ReadWritePaths=
  # names a directory that is not there.
  local dirs; dirs="$(writable_dirs "$ENV_FILE" "$HERE" "$STATE_DIR")"
  local d
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    if [[ ! -d "$d" ]]; then
      mkdir -p -- "$d"
      chown "${OWNER}:${GROUP}" -- "$d"
      chmod 700 -- "$d"
      info "Created ${d} for the store."
    fi
  done <<<"$dirs"
  local RW; RW="$(rw_paths_value <<<"$dirs")"

  local tmp; tmp="$(mktemp)"
  render_unit "$TEMPLATE" "$OWNER" "$GROUP" "$HERE" "$NODE_BIN" "$RW" "$extras" > "$tmp"
  install -m 644 "$tmp" "$UNIT_PATH"
  rm -f "$tmp"
  info "Writable for the service: $(tr '\n' ' ' <<<"$dirs")"

  systemctl daemon-reload
  systemctl enable "$UNIT_NAME" >/dev/null
  systemctl restart "$UNIT_NAME"
  sleep 2

  if systemctl is-active --quiet "$UNIT_NAME"; then
    info "${UNIT_NAME} is running as ${OWNER} from ${HERE}."
    # The token-bearing URL is kept out of the journal, which far more accounts
    # can read than the owner-only file it is written to instead. It sits
    # beside the store, wherever CFG_PATH put that.
    local cfg; cfg="$(env_value "$ENV_FILE" CFG_PATH)"
    local ACCESS_FILE="${STATE_DIR}/dashboard-url.txt"
    [[ -n "$cfg" ]] && ACCESS_FILE="$(dirname -- "$(resolve_path "$cfg" "$HERE")")/dashboard-url.txt"
    for _ in 1 2 3 4 5; do [[ -f "$ACCESS_FILE" ]] && break; sleep 1; done
    if [[ -f "$ACCESS_FILE" ]]; then
      info "Dashboard URL (token included), from ${ACCESS_FILE}:"
      echo ""
      cat "$ACCESS_FILE"
      echo ""
    else
      warn "${ACCESS_FILE} has not appeared yet — read it once the service is up."
    fi
    journalctl -u "$UNIT_NAME" -n 15 --no-pager 2>/dev/null || true
    echo ""
    info "Follow it with:  journalctl -u ${UNIT_NAME} -f"
    info "Change settings in ${ENV_FILE}, then: systemctl restart ${UNIT_NAME}"
    warn "Turn the health monitor on in the dashboard — it is off by default, and"
    warn "it is the reason for running this as a service at all."
  else
    warn "${UNIT_NAME} failed to start. Recent log:"
    journalctl -u "$UNIT_NAME" -n 20 --no-pager 2>/dev/null || true
    error "Fix the above, then: systemctl restart ${UNIT_NAME}"
  fi
}

# Sourced (by the test suite) rather than run: define the functions only.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
