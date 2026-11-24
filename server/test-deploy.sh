#!/usr/bin/env bash
# Tests for deploy.sh against stubbed ssh and scp. Nothing leaves this machine.
#
# The ssh stub really runs the remote command through bash, with stub sudo,
# id and install on its PATH and a stub `bash` standing in for setup.sh. So
# what is checked is what a server would actually execute: the quoting of
# every VAR=value, the sudo/root switch, and the import of the JSON it returns.
# Each host gets its own home directory, so a move from one server to another
# can be followed end to end.
#
# Run: bash server/test-deploy.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SB="$REPO/server/.deploy-sandbox.$$"
trap 'rm -rf "$SB"' EXIT
REAL_BASH="$(command -v bash)"
fails=0
ok()  { echo "   ✓ $*"; }
bad() { echo "   ✗ $*"; fails=$((fails + 1)); }

setup_stubs() {
  rm -rf "$SB"; mkdir -p "$SB/bin" "$SB/remote" "$SB/remote-bin"
  # scp [opts] SRC USER@HOST:DEST — copy SRC into that host's home, log the call.
  cat > "$SB/bin/scp" <<EOF
#!/usr/bin/env bash
echo "scp \$*" >> "$SB/calls.log"
dst="\${!#}"; login="\${dst%%:*}"; host="\${login#*@}"
[[ -f "$SB/unreachable" ]] && grep -qx "\$login" "$SB/unreachable" && exit 1
src=""
for a in "\$@"; do [[ -f "\$a" ]] && src="\$a"; done
mkdir -p "$SB/remote/\$host"
[[ -n "\$src" ]] && cp "\$src" "$SB/remote/\$host/\${dst#*:}"
exit 0
EOF
  # ssh [opts] USER@HOST CMD — run CMD the way that server's login shell would.
  # A host listed in \$SB/unreachable does not answer; with \$SB/fail-show, the
  # read-back of the profiles fails as if the connection dropped.
  cat > "$SB/bin/ssh" <<EOF
#!/usr/bin/env bash
echo "ssh \$*" >> "$SB/calls.log"
cmd="\${!#}"
login="\${@: -2:1}"; host="\${login#*@}"
[[ -f "$SB/unreachable" ]] && grep -qx "\$login" "$SB/unreachable" && { echo "ssh: connect to host \$host port 22: Connection timed out" >&2; exit 255; }
if [[ -f "$SB/fail-show" && "\$cmd" == *"--show --json"* ]]; then
  echo "ssh: connect to host \$host port 22: Connection timed out" >&2; exit 255
fi
mkdir -p "$SB/remote/\$host"
HOME="$SB/remote/\$host" PATH="$SB/remote-bin:/usr/bin:/bin" "$REAL_BASH" -c "\$cmd"
EOF
  # Absolute shebangs throughout: `env bash` would find the stub bash below.
  # Not root unless a case says so, so the sudo branch is the one exercised.
  printf '#!%s\n[[ "$1" == -u ]] && { cat "%s/uid" 2>/dev/null || echo 1000; }\n' "$REAL_BASH" "$SB" > "$SB/remote-bin/id"
  printf '#!%s\necho sudo >> "%s/calls.log"\nexec "$@"\n' "$REAL_BASH" "$SB" > "$SB/remote-bin/sudo"
  printf '#!%s\nexit 0\n' "$REAL_BASH" > "$SB/remote-bin/install"
  # "bash /root/setup.sh …", standing in for setup.sh on the host whose home
  # it runs in. It records the environment it was given, answers --show --json
  # with a share link at that host's address, streams a "tarball" for
  # --export-state -, notes what --import-state was handed, and runs a doctor
  # that fails where \$SB/doctor-fail.<host> exists.
  cat > "$SB/remote-bin/bash" <<EOF
#!$REAL_BASH
host="\$(basename "\$HOME")"
{ echo "[\$host] ARGS: \$*"; env | grep -E '^(PROTOCOL|HY2_PASSWORD|HY2_PORT_RANGE)=' | sort; } >> "$SB/setup-runs.log"
case " \$* " in
  *" --show --json "*) echo "hysteria2://pw-deploy-test@\$host:443/?sni=www.bing.com&insecure=1#deploy-test" ;;
  *" --export-state - "*) echo "STATE-FROM-\$host" ;;
  *" --import-state "*)
    f="\${!#}"; echo "[\$host] IMPORTED: \$(cat "\$f" 2>/dev/null || echo MISSING)" >> "$SB/setup-runs.log" ;;
  *" --doctor "*)
    printf '\n── host\n  ✓ no reboot pending\n\n── hysteria2\n'
    if [[ -f "$SB/doctor-fail.\$host" ]]; then printf '  ✗ service hysteria-server is not active\n'; exit 1; fi
    printf '  ✓ service hysteria-server is active\n' ;;
esac
exit 0
EOF
  chmod +x "$SB"/bin/* "$SB"/remote-bin/*
}

# Node may be a native Windows binary under Git Bash, where it cannot resolve
# a POSIX-style /c/... path. `pwd -W` hands back a form both understand.
store_node() { (cd "$SB" && { pwd -W 2>/dev/null || pwd; }); }
# CFG_PATH and OUTPUT_DIR keep every case away from config-gen/servers.json and
# config-gen/output/, which hold your real store and configs.
run_deploy() {
  env PATH="$SB/bin:$PATH" CFG_PATH="$(store_node)/servers.json" OUTPUT_DIR="$(store_node)/output" \
    bash "$REPO/server/deploy.sh" "$@" 2>&1
}
store="$SB/servers.json"
# A field of the store, read with node: js EXPRESSION over `s`.
store_js() { node -e "const s=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));console.log($1)" "$(store_node)/servers.json"; }
state_js() { node -e "const s=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));console.log($1)" "$(store_node)/monitor-state.json"; }

echo "── deploy.sh installs through sudo, quotes every value, and imports the result"
setup_stubs
out=$(run_deploy -p 2222 ubuntu@203.0.113.7 PROTOCOL=hysteria2 "HY2_PASSWORD=p@ss w'rd \$(touch $SB/pwned)" HY2_PORT_RANGE=20000-30000 --config "$(store_node)/servers.json"); rc=$?
if [[ $rc -eq 0 ]] && grep -qx 'PROTOCOL=hysteria2' "$SB/setup-runs.log" \
   && grep -qxF "HY2_PASSWORD=p@ss w'rd \$(touch $SB/pwned)" "$SB/setup-runs.log" \
   && grep -qx 'HY2_PORT_RANGE=20000-30000' "$SB/setup-runs.log" && [[ ! -e "$SB/pwned" ]]; then
  ok "the server got each value exactly as typed, and none of it ran as a command"
else
  bad "rc=$rc"; echo "$out" | tail -8 | sed 's/^/     /'; cat "$SB/setup-runs.log" 2>/dev/null | sed 's/^/     /'
fi
if grep -q 'ARGS: /root/setup.sh$' "$SB/setup-runs.log" && grep -q '^sudo$' "$SB/calls.log" \
   && grep -q -- '-P 2222' "$SB/calls.log" && grep -q -- '-p 2222' "$SB/calls.log"; then
  ok "setup.sh ran from /root/setup.sh under sudo, with the port given to scp (-P) and ssh (-p)"
else
  bad "unexpected calls"; sed 's/^/     /' "$SB/calls.log"
fi
if grep -q 'pw-deploy-test' "$store" 2>/dev/null && grep -q 'HY2_PASSWORD' <<<"$out" && ! grep -q "p@ss" <<<"$out"; then
  ok "the profile was imported, and the password never reached the terminal"
else
  bad "import or echo wrong"; echo "$out" | sed 's/^/     /'
fi
if [[ "$(store_js 's.hosts.map((h) => h.target + " " + h.port + " " + h.addresses).join()')" == "ubuntu@203.0.113.7 2222 203.0.113.7" ]]; then
  ok "how to reach it was recorded for --all: login, port and the address its clients use"
else
  bad "host not recorded: $(store_js 'JSON.stringify(s.hosts)')"
fi
first_id=$(store_js 's.profiles[0].id')

echo "── a second deploy of an unchanged server is not a failure"
out=$(run_deploy -p 2222 ubuntu@203.0.113.7 PROTOCOL=hysteria2 --config "$(store_node)/servers.json"); rc=$?
if [[ $rc -eq 0 ]] && grep -q 'Nothing new was imported' <<<"$out" && [[ "$(store_js 's.hosts.length')" == 1 ]]; then
  ok "exit 0, says nothing new was imported, and keeps one record for the server"
else bad "rc=$rc"; echo "$out" | tail -5 | sed 's/^/     /'; fi

echo "── a read-back that fails is an error, not \"nothing new\""
touch "$SB/fail-show"
out=$(run_deploy ubuntu@198.51.100.20 PROTOCOL=hysteria2); rc=$?
rm -f "$SB/fail-show"
if [[ $rc -ne 0 ]] && grep -q 'could not be read back over ssh (exit 255)' <<<"$out" \
   && grep -q "ssh ubuntu@198.51.100.20 'sudo bash /root/setup.sh --show --json'" <<<"$out" \
   && ! grep -q 'Nothing new' <<<"$out" && ! grep -q '^Next:' <<<"$out"; then
  ok "exit ${rc}, with the command to import once the server answers"
else
  bad "rc=$rc"; echo "$out" | tail -6 | sed 's/^/     /'
fi

echo "── as root there is no sudo; a setup.sh flag is passed through and nothing is imported"
setup_stubs
echo 0 > "$SB/uid"
out=$(run_deploy root@203.0.113.7 --doctor); rc=$?
if [[ $rc -eq 0 ]] && ! grep -q '^sudo$' "$SB/calls.log" && grep -q 'ARGS: /root/setup.sh --doctor$' "$SB/setup-runs.log" \
   && ! grep -q -- '--show --json' "$SB/setup-runs.log" && grep -q '✓ service hysteria-server is active' <<<"$out"; then
  ok "ran --doctor as root directly, showed its report, and stopped there"
else
  bad "rc=$rc"; sed 's/^/     /' "$SB/calls.log" "$SB/setup-runs.log" 2>/dev/null
fi

echo "── --import-state FILE: a local file is uploaded, imported, and removed"
setup_stubs
echo "LOCAL-STATE" > "$SB/local-state.tgz"
out=$(run_deploy root@203.0.113.7 --import-state "$SB/local-state.tgz"); rc=$?
if [[ $rc -eq 0 ]] && grep -q '\[203.0.113.7\] IMPORTED: LOCAL-STATE' "$SB/setup-runs.log" \
   && [[ ! -e "$SB/remote/203.0.113.7/airport-state.tgz" ]] && grep -q 'pw-deploy-test' "$store" 2>/dev/null; then
  ok "uploaded, imported by setup.sh, deleted from the server, and the profiles imported here"
else
  bad "rc=$rc"; echo "$out" | tail -6 | sed 's/^/     /'; sed 's/^/     /' "$SB/setup-runs.log"
fi
out=$(run_deploy root@203.0.113.7 --import-state /root/elsewhere.tgz); rc=$?
if grep -q 'ARGS: /root/setup.sh --import-state /root/elsewhere.tgz$' "$SB/setup-runs.log"; then
  ok "a path that is not on this computer is passed through as the server's own"
else
  bad "rc=$rc"; sed 's/^/     /' "$SB/setup-runs.log"
fi

echo "── --export-state - hands the server's tarball to this computer, unmangled"
out=$(run_deploy root@203.0.113.7 --export-state - 2>/dev/null); rc=$?
if [[ $rc -eq 0 ]] && grep -qx 'STATE-FROM-203.0.113.7' <<<"$out" && ! grep -q 'ssh -t' <(tail -1 "$SB/calls.log"); then
  ok "streamed to stdout, without a terminal in the way"
else
  bad "rc=$rc"; echo "$out" | sed 's/^/     /'; tail -2 "$SB/calls.log" | sed 's/^/     /'
fi

echo "── ssh options: -J and safe -o are remembered; one that runs commands is not"
setup_stubs
out=$(run_deploy -J admin@bastion.example:2200 -o StrictHostKeyChecking=accept-new -o 'ProxyCommand=touch /tmp/x' \
      ubuntu@203.0.113.7 PROTOCOL=hysteria2); rc=$?
if [[ $rc -eq 0 ]] && grep -q -- '-o ProxyJump=admin@bastion.example:2200' "$SB/calls.log" \
   && [[ "$(store_js 's.hosts[0].jump + " " + s.hosts[0].options.join(",")')" == "admin@bastion.example:2200 StrictHostKeyChecking=accept-new" ]] \
   && grep -q 'Not remembered: ssh option ProxyCommand' <<<"$out"; then
  ok "used for this run, and only the safe ones stored"
else
  bad "rc=$rc"; echo "$out" | tail -4 | sed 's/^/     /'; store_js 'JSON.stringify(s.hosts)' | sed 's/^/     /'
fi

echo "── --all --doctor visits every recorded server and files each result"
setup_stubs
run_deploy -p 2222 ubuntu@203.0.113.7 PROTOCOL=hysteria2 >/dev/null
run_deploy root@198.51.100.4 PROTOCOL=hysteria2 >/dev/null
touch "$SB/doctor-fail.198.51.100.4"
: > "$SB/calls.log"
out=$(run_deploy --all --doctor); rc=$?
if [[ $rc -ne 0 ]] && grep -q '1 of 2 server(s) failed' <<<"$out" \
   && grep -q -- '-p 2222 ubuntu@203.0.113.7' "$SB/calls.log" \
   && [[ "$(state_js 'Object.values(s.doctor).map((d) => d.ok + ":" + d.failures.join("|")).sort().join(" ")')" == "false:hysteria2: service hysteria-server is not active true:" ]]; then
  ok "both visited the recorded way, the failure counted, and both results saved"
else
  bad "rc=$rc"; echo "$out" | tail -8 | sed 's/^/     /'; state_js 'JSON.stringify(s.doctor)' 2>&1 | sed 's/^/     /'
fi
out=$(run_deploy --list); rc=$?
if [[ $rc -eq 0 ]] && grep -q 'root@198.51.100.4' <<<"$out" && grep -q '✗ hysteria2: service hysteria-server is not active' <<<"$out" \
   && grep -q 'ubuntu@203.0.113.7  (port 2222)' <<<"$out"; then
  ok "--list shows each server and what its last doctor found"
else
  bad "rc=$rc"; echo "$out" | sed 's/^/     /'
fi
echo "ubuntu@203.0.113.7" > "$SB/unreachable"
out=$(run_deploy --all --doctor); rc=$?
if [[ $rc -ne 0 ]] && grep -q 'Could not reach ubuntu@203.0.113.7' <<<"$out" \
   && state_js 'Object.values(s.doctor).some((d) => /could not reach/.test(d.error || ""))' | grep -qx true; then
  ok "an unreachable server is reported and recorded as such, and the rest still run"
else
  bad "rc=$rc"; echo "$out" | tail -5 | sed 's/^/     /'
fi
rm -f "$SB/unreachable"
out=$(run_deploy --all --uninstall); rc=$?
if [[ $rc -ne 0 ]] && grep -q 'exactly one of --doctor, --upgrade or --show' <<<"$out"; then ok "--all refuses anything but --doctor, --upgrade or --show"
else bad "rc=$rc: $out"; fi

echo "── --migrate-from moves the keys and re-points the same profiles"
setup_stubs
run_deploy -p 2222 ubuntu@203.0.113.7 PROTOCOL=hysteria2 >/dev/null
first_id=$(store_js 's.profiles[0].id')
: > "$SB/calls.log"; : > "$SB/setup-runs.log"
out=$(run_deploy root@198.51.100.4 --migrate-from ubuntu@203.0.113.7); rc=$?
if [[ $rc -eq 0 ]] && grep -q '\[198.51.100.4\] IMPORTED: STATE-FROM-203.0.113.7' "$SB/setup-runs.log" \
   && [[ ! -e "$SB/remote/198.51.100.4/airport-state.tgz" ]]; then
  ok "the old server's state reached the new one's setup.sh, and the copy there is gone"
else
  bad "rc=$rc"; echo "$out" | tail -8 | sed 's/^/     /'; sed 's/^/     /' "$SB/setup-runs.log"
fi
if grep -q -- '-p 2222 ubuntu@203.0.113.7' "$SB/calls.log" && grep -q 'ssh.* root@198.51.100.4' "$SB/calls.log" \
   && ! grep -q -- '-p 2222 root@198.51.100.4' "$SB/calls.log" && ! grep -rq 'STATE-FROM' "$SB/remote/203.0.113.7" 2>/dev/null; then
  ok "the old server was reached the recorded way, and the state never rested on its disk"
else
  bad "unexpected calls"; sed 's/^/     /' "$SB/calls.log"
fi
if [[ "$(store_js 's.profiles.length + " " + s.profiles[0].server + " " + s.profiles[0].id')" == "1 198.51.100.4 ${first_id}" ]] \
   && [[ "$(store_js 's.hosts.map((h) => h.target).join()')" == "root@198.51.100.4" ]] \
   && grep -q 'Moved "deploy-test" (hysteria2) from 203.0.113.7 to 198.51.100.4' <<<"$out"; then
  ok "one profile, same id, new address; the old server's record replaced by the new one's"
else
  bad "store: $(store_js 'JSON.stringify({p: s.profiles.map((p) => [p.id, p.server]), h: s.hosts})')"
fi
out=$(run_deploy root@198.51.100.4 --migrate-from ubuntu@203.0.113.7 --doctor); rc=$?
if [[ $rc -ne 0 ]] && grep -q 'does not combine with --doctor' <<<"$out"; then ok "and it refuses setup.sh flags other than --force"
else bad "rc=$rc: $out"; fi

echo "── bad input is refused before anything is copied"
setup_stubs
for args in "203.0.113.7" "ubuntu@h lower=1" "ubuntu@h 'A;B=1'" "-p x ubuntu@h" "ubuntu@h -o ''" \
            "ubuntu@h --migrate-from -oProxyCommand=x" "'bad host@h'" "ubuntu@h --import-state"; do
  eval "set -- $args"
  if run_deploy "$@" >/dev/null; then bad "accepted: $args"
  elif [[ -s "$SB/calls.log" ]]; then bad "refused, but only after connecting: $args"
  else ok "refused: $args"; fi
done

echo ""
if [[ $fails -eq 0 ]]; then echo "deploy.sh: all passed"; exit 0; fi
echo "deploy.sh: ${fails} failed"; exit 1
