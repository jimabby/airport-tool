#!/usr/bin/env bash
# Set up a VPS from your own computer in one command, and look after it after.
#
#   bash server/deploy.sh [options] USER@HOST [VAR=value ...] [--setup-flag ...]
#   bash server/deploy.sh [options] USER@NEW --migrate-from USER@OLD [VAR=value ...]
#   bash server/deploy.sh --all --doctor | --upgrade | --show
#   bash server/deploy.sh --list
#
# Setting up: it copies setup.sh to the server, runs it as root (through sudo
# when USER is not root, which is how Oracle Cloud, AWS and Google Cloud images
# log you in), then pulls every installed protocol back as JSON and imports it
# into config-gen, which writes the client configs. It also records how you
# reached the server (login, port, key, jump host), so --all and --migrate-from
# need not be told again. The credentials travel over the ssh connection and a
# pipe, never through a file on this machine.
#
# Examples:
#   bash server/deploy.sh ubuntu@203.0.113.9 PROTOCOL=reality
#   bash server/deploy.sh -i ~/.ssh/oracle.key ubuntu@203.0.113.9 PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000
#   bash server/deploy.sh root@203.0.113.9 --doctor      # any setup.sh flag goes through as-is
#   bash server/deploy.sh root@203.0.113.9 --import-state ./airport-state.tgz   # a local file is uploaded
#   bash server/deploy.sh root@203.0.113.9 --export-state - > airport-state.tgz # a backup, to this computer
#
# Moving to a new VPS (when the old one's address gets blocked):
#   bash server/deploy.sh root@198.51.100.4 --migrate-from ubuntu@203.0.113.9
# streams the old server's keys straight to the new one (never stored here or
# left on the old disk), re-creates every protocol there with the same
# credentials, and re-points the profiles in config-gen at the new address —
# same ids, probe history and device subsets. Clients on the subscription URL
# pick up the new address on their next refresh. The old server keeps running
# until you delete it.
#
# Every server deploy.sh has set up, in one go:
#   bash server/deploy.sh --all --doctor     # results also show in the dashboard
#   bash server/deploy.sh --all --upgrade    # to this repo's pinned Xray / Hysteria / sing-box
#   bash server/deploy.sh --list             # what is recorded, and the last doctor result
#
# Options:
#   -i FILE         ssh private key
#   -p PORT         ssh port (default 22)
#   -J JUMP         jump host, [USER@]HOST[:PORT], as ssh -J takes it
#   -o NAME=VALUE   an ssh option, e.g. -o StrictHostKeyChecking=accept-new (repeatable).
#                   Only connection options are remembered for --all — never one
#                   that could run a command, such as ProxyCommand.
#   --config FILE   config-gen store to import into (default: config-gen/servers.json)
#   --no-import     install only; do not touch config-gen
#   -h, --help      this text
#
# VAR=value pairs are setup.sh's environment knobs (see `bash server/setup.sh --help`).
# Other arguments starting with -- are passed to setup.sh. Every run copies this
# repo's setup.sh over first, so a server always runs the version you have.
# Works from Linux, macOS and Git Bash on Windows; needs ssh, scp and (to
# import, record or use --all) Node. --doctor and --all capture what the server
# prints, so sudo cannot ask for a password there: log in as root, or as a user
# with passwordless sudo (every cloud image's default user has it).

set -euo pipefail
# macOS still ships bash 3.2, where "${a[@]}" on an empty array is an unbound
# variable under set -u, so every optional array is expanded as ${a[@]+…}.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
SETUP="$HERE/setup.sh"
GEN="$REPO/config-gen/gen.js"
HOSTS="$REPO/config-gen/hosts.js"
# Where the script lives on the server. /root/setup.sh is the path the README's
# server-management commands use, so `sudo bash /root/setup.sh --doctor` works.
REMOTE_SETUP=/root/setup.sh

die()  { echo "deploy: $*" >&2; exit 1; }
say()  { echo -e "\033[0;32m[deploy]\033[0m $*" >&2; }
warn() { echo -e "\033[1;33m[deploy]\033[0m $*" >&2; }
usage() { sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'; exit 0; }

# USER@HOST, as ssh takes it. Nothing may start with "-", or ssh would read it
# as an option; the same rule config-gen/lib/hosts.js holds a stored one to.
LOGIN_RE='^[A-Za-z0-9._][A-Za-z0-9._-]*@[A-Za-z0-9._:][A-Za-z0-9._:-]*$'

# How to reach the server named on the command line.
key=""; port=""; jump=""; opts=()
config=""
do_import=1
target=""
envs=()
flags=()
migrate_from=""
all=0
list=0
import_local=""

while [[ $# -gt 0 ]]; do
  a="$1"; shift
  case "$a" in
    -h|--help) usage ;;
    -i) [[ $# -gt 0 ]] || die "-i needs a key file"
        [[ -r "$1" ]] || die "cannot read key file $1"
        # Absolute, so --all can use it from wherever it is run.
        key="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; shift ;;
    -p) [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] || die "-p needs a port number"
        port="$1"; shift ;;
    -J) [[ $# -gt 0 && -n "$1" && "$1" != -* ]] || die "-J needs a jump host ([USER@]HOST[:PORT])"
        jump="$1"; shift ;;
    -o) [[ $# -gt 0 && "$1" == ?*=* && "$1" != -* ]] || die "-o needs an ssh option, e.g. -o ConnectTimeout=10"
        opts+=("$1"); shift ;;
    --config) [[ $# -gt 0 ]] || die "--config needs a file"; config="$1"; shift ;;
    --no-import) do_import=0 ;;
    --all) all=1 ;;
    --list) list=1 ;;
    --migrate-from)
      [[ $# -gt 0 && "$1" =~ $LOGIN_RE ]] || die "--migrate-from needs the old server as USER@HOST"
      migrate_from="$1"; shift ;;
    # setup.sh takes the file as the next argument, or after "=".
    --import-state|--export-state|--import-state=*|--export-state=*)
      if [[ "$a" == *=* ]]; then f="${a#*=}"; a="${a%%=*}"
      else
        [[ $# -gt 0 && -n "$1" && "$1" != --* ]] || die "$a needs a file name (e.g. $a /root/airport-state.tgz)"
        f="$1"; shift
      fi
      [[ -n "$f" ]] || die "$a needs a file name"
      # A file that exists here is the one you mean: it is uploaded first.
      if [[ "$a" == --import-state && -f "$f" ]]; then import_local="$f"
      else flags+=("$a" "$f"); fi ;;
    --*) flags+=("$a") ;;
    -*) die "unknown option $a (try --help)" ;;
    *=*)
      name="${a%%=*}"
      # Only setup.sh-shaped names. The value is quoted for the remote shell
      # below; the name is not, so it must be a plain identifier.
      [[ "$name" =~ ^[A-Z][A-Z0-9_]*$ ]] || die "not an environment variable name: $name"
      envs+=("$a") ;;
    *)
      [[ -z "$target" ]] || die "unexpected argument: $a"
      [[ "$a" == *@* ]] || die "give the server as USER@HOST (e.g. ubuntu@203.0.113.9)"
      [[ "$a" =~ $LOGIN_RE ]] || die "not an ssh login: $a"
      target="$a" ;;
  esac
done

qc=()
[[ -n "$config" ]] && qc=(--config "$config")
have_node() { command -v node >/dev/null 2>&1; }

if [[ $list -eq 1 ]]; then
  have_node || die "--list reads the store with Node, which is not installed here."
  node "$HOSTS" show ${qc[@]+"${qc[@]}"}
  exit 0
fi

if [[ $all -eq 1 ]]; then
  [[ -z "$target" && -z "$migrate_from" && -z "$import_local" ]] || die "--all visits every recorded server — leave out USER@HOST"
  if [[ ${#flags[@]} -ne 1 ]] || [[ "${flags[0]}" != --doctor && "${flags[0]}" != --upgrade && "${flags[0]}" != --show ]]; then
    die "--all takes exactly one of --doctor, --upgrade or --show"
  fi
else
  [[ -n "$target" ]] || usage
fi
if [[ -n "$migrate_from" ]]; then
  [[ "$migrate_from" != "$target" ]] || die "--migrate-from names the old server; ${target} is the new one"
  [[ -z "$import_local" ]] || die "--migrate-from brings the state itself; leave out --import-state"
  for f in ${flags[@]+"${flags[@]}"}; do
    [[ "$f" == --force ]] || die "--migrate-from does not combine with $f (only --force, to replace a different install on the new server)"
  done
fi
[[ -f "$SETUP" ]] || die "cannot find $SETUP"
command -v ssh >/dev/null 2>&1 || die "ssh is not installed"
command -v scp >/dev/null 2>&1 || die "scp is not installed"

# One quoted word per argument, safe to paste into the remote shell.
quote_all() { local out="" w; for w in "$@"; do out+=" $(printf '%q' "$w")"; done; printf '%s' "$out"; }

# Run as root on the server: directly when we are root, through sudo otherwise.
# `sudo env` rather than `sudo VAR=…`: sudo's own env_reset would drop them.
as_root() { printf 'if [ "$(id -u)" -eq 0 ]; then %s; else sudo %s; fi' "$1" "$1"; }

# ssh / scp options for one server: set_conn KEY PORT JUMP [NAME=VALUE …].
SSH_O=(); SCP_O=()
set_conn() {
  local k="$1" p="$2" j="$3" o
  shift 3
  SSH_O=(); SCP_O=()
  if [[ -n "$k" ]]; then SSH_O+=(-i "$k"); SCP_O+=(-i "$k"); fi
  if [[ -n "$p" ]]; then SSH_O+=(-p "$p"); SCP_O+=(-P "$p"); fi
  if [[ -n "$j" ]]; then SSH_O+=(-o "ProxyJump=$j"); SCP_O+=(-o "ProxyJump=$j"); fi
  for o in "$@"; do SSH_O+=(-o "$o"); SCP_O+=(-o "$o"); done
}
cli_conn() { set_conn "$key" "$port" "$jump" ${opts[@]+"${opts[@]}"}; }
rssh() { ssh ${SSH_O[@]+"${SSH_O[@]}"} "$@"; }

# Loads a recorded server's connection (a `hosts.js list` line) into SSH_O /
# SCP_O, and its id and login into REC_ID / REC_TARGET.
REC_ID=""; REC_TARGET=""
use_record() {
  local p k j o extra=()
  IFS=$'\x1f' read -r REC_ID REC_TARGET p k j o <<<"$1"
  if [[ -n "$o" ]]; then IFS=$'\x1e' read -r -a extra <<<"$o"; fi
  set_conn "$k" "$p" "$j" ${extra[@]+"${extra[@]}"}
}

# Copy this repo's setup.sh over; REMOTE_INSTALL, run at the start of the next
# ssh command, puts it at /root/setup.sh.
push_setup() { scp -q ${SCP_O[@]+"${SCP_O[@]}"} "$SETUP" "${1}:airport-setup.sh"; }
REMOTE_INSTALL="$(as_root "install -m 700 \"\$HOME/airport-setup.sh\" $REMOTE_SETUP") && rm -f \"\$HOME/airport-setup.sh\""

# setup.sh as root, with the VAR=value pairs from the command line and then $1
# (already quoted for the remote shell).
setup_cmd() { as_root "env$(quote_all ${envs[@]+"${envs[@]}"}) bash ${REMOTE_SETUP}${1:-}"; }

# A command to paste, using the connection currently in SSH_O.
sudo_for() { [[ "${1%%@*}" == root ]] || printf 'sudo '; }
show_hint() {
  printf "ssh%s %s '%sbash %s --show --json' | node config-gen/gen.js --add -" \
    "$(quote_all ${SSH_O[@]+"${SSH_O[@]}"})" "$1" "$(sudo_for "$1")" "$REMOTE_SETUP"
}

ensure_deps() {
  have_node || return 1
  if [[ ! -d "$REPO/config-gen/node_modules" ]]; then
    command -v npm >/dev/null 2>&1 || die "Node is installed but npm is not; install npm, then run: cd config-gen && npm install"
    say "Installing config-gen dependencies…"
    (cd "$REPO/config-gen" && npm install --no-audit --no-fund >/dev/null)
  fi
}

# Read the server's profiles back and import them into config-gen, then record
# how to reach it. $2: addresses the server just moved away from (re-point those
# profiles instead of adding new ones). $3: the old server's login, whose record
# this one replaces.
import_and_record() {
  local t="$1" moved="${2:-}" replaces="${3:-}" json rc=0 gen_args=(--add -) rec
  ensure_deps || die "the server is set up, but Node is not installed here to import it. Install Node 18+, then: $(show_hint "$t")"
  say "Reading the server's profiles back…"
  json=$(rssh "$t" "$(as_root "bash $REMOTE_SETUP --show --json")") || rc=$?
  # A failure here is not "nothing new": the import never got anything to
  # look at. Saying so with exit 0 used to send people on to step 4 with no
  # configs to import.
  if [[ $rc -ne 0 || -z "${json//[[:space:]]/}" ]]; then
    die "the server is set up, but its profiles could not be read back over ssh (exit ${rc}). Import them once it answers: $(show_hint "$t")"
  fi
  [[ -n "$config" ]] && gen_args+=(--config "$config")
  [[ -n "$moved" ]] && gen_args+=(--moved-from "$moved")
  say "Importing the server's profiles into config-gen…"
  # gen.js writes every client config straight after a successful import. It
  # finds its store and output/ by its own location, so no cd: a relative
  # --config stays relative to where you ran this. Re-deploying a server whose
  # keys did not change imports nothing new, and gen.js says so with a non-zero
  # exit — that is not a failed deploy.
  if printf '%s\n' "$json" | node "$GEN" "${gen_args[@]}"; then
    say "Client configs written to config-gen/output/ (clash-config.yaml, singbox-config.json, qrcode.png, …)."
  else
    warn "Nothing new was imported — this server's profiles are already in the store (or see the message above)."
  fi
  rec=(record --target "$t")
  [[ -n "$port" ]] && rec+=(--port "$port")
  [[ -n "$key" ]] && rec+=(--key "$key")
  [[ -n "$jump" ]] && rec+=(--jump "$jump")
  for o in ${opts[@]+"${opts[@]}"}; do rec+=(--option "$o"); done
  [[ -n "$replaces" ]] && rec+=(--replaces "$replaces")
  printf '%s\n' "$json" | node "$HOSTS" "${rec[@]}" ${qc[@]+"${qc[@]}"} \
    || warn "Could not record ${t} for --all; the profiles were imported all the same."
}

# setup.sh --doctor on $1, printed, and filed under host id $2 if it has one.
# Captured rather than streamed, so it can be saved — which is also why sudo
# cannot stop to ask for a password here.
run_doctor() {
  local t="$1" id="${2:-}" out rc=0
  out=$(rssh "$t" "$REMOTE_INSTALL && $(setup_cmd " --doctor")" 2>&1) || rc=$?
  printf '%s\n' "$out"
  if [[ -n "$id" ]] && have_node; then
    printf '%s\n' "$out" | node "$HOSTS" doctor "$id" --exit "$rc" ${qc[@]+"${qc[@]}"} \
      || warn "Could not save the result for the dashboard."
  fi
  if [[ $rc -ne 0 ]] && grep -qiE 'terminal is required|password is required' <<<"$out"; then
    warn "sudo on ${t} wants a password, which --doctor cannot type. Log in as root, or give $(printf '%s' "${t%%@*}") passwordless sudo."
  fi
  return "$rc"
}

next_steps() {
  cat >&2 <<EOF

Next:
  1. Open the port setup.sh printed in your cloud provider's firewall too
     (Oracle: VCN → Security List; AWS: Security Group; GCP: VPC firewall rule).
  2. Check every server you have set up:   bash server/deploy.sh --all --doctor
  3. Or manage it all in the dashboard:   cd web-ui && npm install && npm start
EOF
}

# ── --all ──────────────────────────────────────────────────────────────────── #
run_all() {
  local lines=() l n=0 failed=0 rc action="${flags[0]}" tty=()
  have_node || die "--all reads the recorded servers with Node, which is not installed here."
  while IFS= read -r l; do [[ -n "$l" ]] && lines+=("$l"); done < <(node "$HOSTS" list ${qc[@]+"${qc[@]}"})
  [[ ${#lines[@]} -gt 0 ]] || die "No servers recorded yet. deploy.sh records each one it sets up, e.g.: bash server/deploy.sh ubuntu@IP PROTOCOL=reality"
  # A terminal for sudo on --upgrade and --show, when there is one to give.
  [[ -t 0 && -t 1 ]] && tty=(-t)
  for l in "${lines[@]}"; do
    use_record "$l"
    n=$((n + 1))
    echo "" >&2
    say "── ${REC_TARGET} (${n} of ${#lines[@]}): setup.sh ${action}"
    rc=0
    if ! push_setup "$REC_TARGET"; then
      warn "Could not reach ${REC_TARGET}."
      [[ "$action" == --doctor ]] && printf 'could not reach %s over ssh to run --doctor\n' "$REC_TARGET" \
        | node "$HOSTS" doctor "$REC_ID" --exit 255 ${qc[@]+"${qc[@]}"} || true
      failed=$((failed + 1)); continue
    fi
    case "$action" in
      --doctor) run_doctor "$REC_TARGET" "$REC_ID" || rc=$? ;;
      *) rssh ${tty[@]+"${tty[@]}"} "$REC_TARGET" "$REMOTE_INSTALL && $(setup_cmd " ${action}")" || rc=$? ;;
    esac
    [[ $rc -eq 0 ]] || failed=$((failed + 1))
  done
  echo "" >&2
  if [[ $failed -eq 0 ]]; then say "All ${n} server(s): setup.sh ${action} succeeded."; exit 0; fi
  warn "${failed} of ${n} server(s) failed setup.sh ${action} — see above."
  exit 1
}

# ── --migrate-from ─────────────────────────────────────────────────────────── #
migrate() {
  local old="$migrate_from" old_rec="" old_json old_addrs=""
  # The old server is reached the way deploy.sh recorded it; one it never set
  # up, with the same options as the new one.
  if have_node; then old_rec=$(node "$HOSTS" lookup "$old" ${qc[@]+"${qc[@]}"}) || old_rec=""; fi
  old_conn() { if [[ -n "$old_rec" ]]; then use_record "$old_rec"; else cli_conn; fi; }

  old_conn
  say "Reading ${old}'s profiles (nothing there is changed)…"
  push_setup "$old" || die "could not copy setup.sh to ${old}. Nothing has been changed anywhere."
  old_json=$(rssh "$old" "$REMOTE_INSTALL && $(as_root "bash $REMOTE_SETUP --show --json")") \
    || die "could not read ${old}'s profiles over ssh. Nothing has been changed anywhere."
  if [[ $do_import -eq 1 ]]; then
    ensure_deps || die "moving a server re-points its profiles in config-gen, which needs Node 18+ here (or pass --no-import)."
    old_addrs=$(printf '%s\n' "$old_json" | node "$HOSTS" addresses)
  fi

  cli_conn
  say "Copying setup.sh to ${target}…"
  push_setup "$target" || die "could not copy setup.sh to ${target}. ${old} is untouched."
  say "Moving the keys from ${old} to ${target} — straight through, never stored on this computer…"
  # Each end of the pipe is its own subshell, so each sets up its own server's
  # connection.
  if ! { old_conn; rssh "$old" "$(as_root "bash $REMOTE_SETUP --export-state -")"; } \
     | { cli_conn; rssh "$target" 'umask 077 && cat > "$HOME/airport-state.tgz"'; }; then
    rssh "$target" 'rm -f "$HOME/airport-state.tgz"' >/dev/null 2>&1 || true
    die "could not carry the state from ${old} to ${target}. ${old} is untouched and still serving."
  fi
  say "Re-creating every protocol on ${target} with ${old}'s keys…"
  # The tarball holds every private key: it goes whether the import worked or not.
  rssh -t "$target" \
    "$REMOTE_INSTALL && $(setup_cmd " --import-state \"\$HOME/airport-state.tgz\"$(quote_all ${flags[@]+"${flags[@]}"})"); rc=\$?; rm -f \"\$HOME/airport-state.tgz\"; exit \$rc" \
    || die "the import on ${target} failed (see above). ${old} is untouched and still serving."

  if [[ $do_import -eq 1 ]]; then
    import_and_record "$target" "$old_addrs" "$old"
  fi
  cat >&2 <<EOF

${target} now serves ${old}'s keys at its own address.
  • Devices on a subscription URL pick up the new address on their next refresh.
  • Devices that imported a file need it again, from config-gen/output/ or the dashboard.
  • Profiles that name a domain rather than an IP need its DNS record pointed at ${target}.
${old} is still running. Open the ports in ${target}'s cloud firewall, check it with
  bash server/deploy.sh ${target} --doctor
and delete the old VPS at your provider once your devices connect.
EOF
}

[[ $all -eq 1 ]] && run_all
[[ -n "$migrate_from" ]] && { migrate; exit 0; }

# ── One server ─────────────────────────────────────────────────────────────── #
cli_conn
say "Copying setup.sh to ${target}…"
push_setup "$target"

# The one flag run that is saved: a recorded server's --doctor also feeds --list
# and the dashboard.
if [[ ${#flags[@]} -eq 1 && "${flags[0]}" == --doctor && -z "$import_local" ]]; then
  id=""
  if have_node && rec=$(node "$HOSTS" lookup "$target" ${qc[@]+"${qc[@]}"}); then id="${rec%%$'\x1f'*}"; fi
  run_doctor "$target" "$id"
  exit $?
fi

remote_args="$(quote_all ${flags[@]+"${flags[@]}"})"
after=""
if [[ -n "$import_local" ]]; then
  say "Uploading ${import_local}…"
  scp -q ${SCP_O[@]+"${SCP_O[@]}"} "$import_local" "${target}:airport-state.tgz"
  remote_args+=' --import-state "$HOME/airport-state.tgz"'
  # It holds every private key: it goes whether the import worked or not.
  after='; rc=$?; rm -f "$HOME/airport-state.tgz"; exit $rc'
fi

# -t gives sudo a terminal to ask on, for images that want a password — except
# when the output is a tarball, which a terminal would mangle.
tty=(-t)
[[ " ${flags[*]-} " == *" --export-state - "* ]] && tty=()

# Names only: values can be passwords, and this line stays in scrollback.
names=""; for e in ${envs[@]+"${envs[@]}"}; do names+=" ${e%%=*}"; done
say "Running setup.sh on the server${names:+ (with${names})}…"
rssh ${tty[@]+"${tty[@]}"} "$target" "$REMOTE_INSTALL && $(setup_cmd "$remote_args")${after}"

# A flag run (--doctor, --show, --uninstall …) is the whole job — except an
# import, which leaves a server whose profiles belong in config-gen.
is_import=0
[[ -n "$import_local" ]] && is_import=1
for f in ${flags[@]+"${flags[@]}"}; do [[ "$f" == --import-state ]] && is_import=1; done
if [[ ${#flags[@]} -gt 0 && $is_import -eq 0 ]]; then exit 0; fi

if [[ $do_import -eq 0 ]]; then
  say "Done. Import later with: $(show_hint "$target")"
  exit 0
fi

import_and_record "$target"
next_steps
