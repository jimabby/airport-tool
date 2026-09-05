#!/usr/bin/env bash
# Smoke-test setup.sh without touching the machine running it.
#
# Every system command (apt-get, systemctl, curl, xray, iptables, …) is replaced
# by a stub, and every absolute path the script writes to is redirected into a
# throwaway sandbox. Each protocol then runs end to end, and the profile.json it
# produces is fed back through config-gen to prove the two halves agree.
#
# This mostly exists to catch `set -e` aborts and unbound variables — a shell
# script that only ever runs once, on a fresh VPS, is otherwise untested until
# it fails in front of a user who can't easily debug it.
#
# Run: bash server/test-setup.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/server/setup.sh"
# One sandbox per run. It used to be a fixed `.sandbox`, which meant two runs at
# once — a stray background invocation, or two of these in a CI matrix — silently
# deleted each other's fixtures mid-case and reported failures that had nothing
# to do with the code. Removed on exit however the script ends.
SB="$REPO/server/.sandbox.$$"
cleanup_sandbox() { rm -rf "$SB"; }
trap cleanup_sandbox EXIT

# Node may be a native Windows binary under Git Bash, where it cannot resolve a
# POSIX-style /c/... path. `pwd -W` hands back a form both understand.
REPO_NODE="$(cd "$REPO" && { pwd -W 2>/dev/null || pwd; })"

make_stubs() {
  mkdir -p "$SB/bin"

  # Anything that just needs to succeed quietly.
  for cmd in apt-get tar install modprobe chown journalctl sysctl-noop; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$SB/bin/$cmd"
  done

  printf '#!/usr/bin/env bash\n[[ "$1" == "is-active" ]] && exit 0\nexit 0\n' > "$SB/bin/systemctl"

  # curl: return a plausible IP for the address probe, and a no-op script for
  # every installer the real script pipes into bash.
  cat > "$SB/bin/curl" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    *ifconfig.me*) echo "203.0.113.9"; exit 0 ;;
  esac
done
echo "true"
EOF

  cat > "$SB/bin/xray" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  x25519) echo "Private key: PRIVKEYAAA"; echo "Public key: PUBKEYBBB" ;;
  uuid)   echo "11111111-2222-3333-4444-555555555555" ;;
esac
EOF

  # -C (does the rule exist?) fails, so the script takes the insert path.
  #
  # This stub also *validates* --dport the way the real iptables does: a range
  # is written with a colon, and `20000-30000` is rejected outright. The old
  # accept-everything stub is why port hopping shipped for a while passing the
  # firewalld spelling to iptables and ufw, which both refused it while the
  # script printed "Opened". Every rule it accepts is logged so the assertions
  # below can check what was actually asked for.
  cat > "$SB/bin/iptables" <<EOF
#!/usr/bin/env bash
prev=""
check=0
for a in "\$@"; do
  if [[ "\$prev" == "--dport" || "\$prev" == "--to-ports" ]]; then
    if [[ ! "\$a" =~ ^[0-9]+(:[0-9]+)?\$ ]]; then
      echo "iptables: invalid port/port range \\"\$a\\"" >&2
      exit 2
    fi
  fi
  # -C is "does this rule already exist?", and it is not always argument one:
  # the NAT rules pass "-t nat -C PREROUTING …". Matching only \$1 meant every
  # NAT existence check answered "yes, it is already there", so the -A that
  # actually installs port hopping was never exercised by these tests at all.
  [[ "\$a" == "-C" ]] && check=1
  prev="\$a"
done
echo "\$*" >> "${SB}/iptables.log"
# Nothing exists in a fresh sandbox, so every check reports "not found" and the
# script takes the insert path — which is the path worth testing.
[[ \$check -eq 1 ]] && exit 1
exit 0
EOF
  cp "$SB/bin/iptables" "$SB/bin/ip6tables"
  printf '#!/usr/bin/env bash\necho "# rules"\n' > "$SB/bin/iptables-save"
  cp "$SB/bin/iptables-save" "$SB/bin/ip6tables-save"

  cat > "$SB/bin/sysctl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
  *tcp_available_congestion_control*) echo "reno cubic bbr" ;;
  *"-n net.ipv4.tcp_congestion_control"*) echo "bbr" ;;
esac
exit 0
EOF

  printf '#!/usr/bin/env bash\necho "v2ray-plugin v1.3.2"\n' > "$SB/bin/v2ray-plugin"
  printf '#!/usr/bin/env bash\nshift; exec "$@"\n' > "$SB/bin/timeout"
  printf '#!/usr/bin/env bash\necho "203.0.113.9"\n' > "$SB/bin/hostname"
  rm -f "$SB/bin/sysctl-noop"

  # ufw / firewall-cmd are deliberately absent so the iptables fallback — the
  # path Oracle Cloud and AWS images actually take — is what gets exercised.
  chmod +x "$SB"/bin/*
}

# Rewrite absolute paths into the sandbox. Longer prefixes must be substituted
# before shorter ones, or the /etc/ rule mangles /usr/local/etc/ paths.
sandbox_script() {
  mkdir -p "$SB/etc/systemd/system" "$SB/etc/sysctl.d" "$SB/etc/shadowsocks-libev" \
           "$SB/etc/hysteria" "$SB/etc/sing-box" "$SB/usr/local/etc/xray"
  echo 'ID=ubuntu' > "$SB/etc/os-release"
  sed -e "s#^\[\[ \$EUID -ne 0 \]\].*#true#" \
      -e "s#/usr/local/etc/#${SB}/usr/local/etc/#g" \
      -e "s#/usr/local/bin/#${SB}/bin/#g" \
      -e "s#/usr/bin/ss-server#${SB}/bin/ss-server#g" \
      -e "s#/etc/#${SB}/etc/#g" \
      "$SRC" > "$SB/setup.sh"
}

fails=0
# Environment overrides go to `env`; command-line flags must go after the script
# name, or `env` tries to execute "--uninstall" as a program.
sb_run()  { env PATH="$SB/bin:/usr/bin:/bin" "$@" bash "$SB/setup.sh" 2>&1; }
sb_flag() { env PATH="$SB/bin:/usr/bin:/bin" bash "$SB/setup.sh" "$@" 2>&1; }

run_case() {
  local name="$1"; shift
  rm -rf "$SB"
  make_stubs
  sandbox_script

  echo "── $name"
  local out rc
  out=$(sb_run "$@"); rc=$?
  if [[ $rc -ne 0 ]]; then
    echo "   ✗ exited $rc"
    echo "$out" | tail -15 | sed 's/^/     /'
    fails=$((fails + 1)); return
  fi

  local pj="$SB/etc/airport-tool/profile.json"
  if [[ ! -f "$pj" ]]; then
    echo "   ✗ no profile.json written"; fails=$((fails + 1)); return
  fi
  local pj_node; pj_node="$(cd "$SB/etc/airport-tool" && { pwd -W 2>/dev/null || pwd; })/profile.json"
  # The profile the server emits must be one config-gen actually accepts.
  if ! node -e "
    const fs=require('fs');
    const C=require('$REPO_NODE/config-gen/lib/configs.js');
    const p=C.normalizeProfile(JSON.parse(fs.readFileSync('$pj_node','utf8')));
    const v=C.validateProfile(p);
    if (v.errors.length) { console.error('     config-gen rejects it: '+v.errors.join('; ')); process.exit(1); }
    console.log('   ✓ ' + p.protocol + ' → ' + C.buildUri(p).slice(0, 70) + '…');
  "; then
    fails=$((fails + 1)); return
  fi
}

run_case "shadowsocks (websocket)"  PROTOCOL=shadowsocks SS_PASSWORD=testpw
run_case "reality (tcp)"            PROTOCOL=reality
run_case "reality (grpc)"           PROTOCOL=reality REALITY_NETWORK=grpc
run_case "reality (xhttp)"          PROTOCOL=reality REALITY_NETWORK=xhttp
run_case "hysteria2 (self-signed)"  PROTOCOL=hysteria2 HY2_PASSWORD='p@ss w/+='
run_case "hysteria2 (obfs off)"     PROTOCOL=hysteria2 HY2_OBFS=0
run_case "tuic (self-signed)"       PROTOCOL=tuic TUIC_PASSWORD='p@ss w/+='
run_case "hysteria2 (port hopping)" PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000

echo "── unknown protocol is rejected"
if sb_run PROTOCOL=nope >/dev/null 2>&1; then
  echo "   ✗ should have failed"; fails=$((fails + 1))
else
  echo "   ✓ rejected"
fi

# Re-running must not mint new keys — that would silently break every client
# already carrying the old ones.
echo "── re-run reuses keys, FORCE=1 regenerates"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
first=$(grep -o '"shortId": "[^"]*"' "$SB/etc/airport-tool/profile.json")
sb_run PROTOCOL=reality >/dev/null 2>&1
again=$(grep -o '"shortId": "[^"]*"' "$SB/etc/airport-tool/profile.json")
sb_run PROTOCOL=reality FORCE=1 >/dev/null 2>&1
forced=$(grep -o '"shortId": "[^"]*"' "$SB/etc/airport-tool/profile.json")
if [[ "$first" == "$again" && "$first" != "$forced" ]]; then
  echo "   ✓ stable across re-runs, regenerated under FORCE=1"
else
  echo "   ✗ first=$first again=$again forced=$forced"
  fails=$((fails + 1))
fi

# A plain re-run must not move the endpoint. It used to: the reuse path restored
# keys but not REALITY_PORT/REALITY_SNI, so `bash setup.sh` with no environment
# silently reverted them to the defaults and broke every distributed client.
echo "── re-run keeps port and SNI"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality REALITY_PORT=8443 REALITY_SNI=www.amazon.com >/dev/null 2>&1
before=$(grep -oE '"(port|sni)": [^,]*' "$SB/etc/airport-tool/profile.json" | tr '
' ' ')
sb_run PROTOCOL=reality >/dev/null 2>&1
after=$(grep -oE '"(port|sni)": [^,]*' "$SB/etc/airport-tool/profile.json" | tr '
' ' ')
if [[ "$before" == "$after" ]]; then
  echo "   ✓ port and SNI survived a bare re-run"
else
  echo "   ✗ before: $before"
  echo "     after:  $after"
  fails=$((fails + 1))
fi

# An explicit value on a later run must still win over the saved one.
sb_run PROTOCOL=reality REALITY_PORT=9443 >/dev/null 2>&1
if grep -q '"port": 9443' "$SB/etc/airport-tool/profile.json"; then
  echo "   ✓ an explicit REALITY_PORT still overrides the saved one"
else
  echo "   ✗ explicit REALITY_PORT was ignored"; fails=$((fails + 1))
fi

echo "── --show prints without changing anything"
before_show=$(cat "$SB/etc/airport-tool/profile.json")
out=$(sb_flag --show 2>&1)
after_show=$(cat "$SB/etc/airport-tool/profile.json")
if [[ "$before_show" == "$after_show" ]] && grep -q "REALITY_UUID" <<<"$out"; then
  echo "   ✓ printed the saved details and left the install alone"
else
  echo "   ✗ --show did not print details, or modified state"; fails=$((fails + 1))
fi

# A port range only helps if it reaches the client, and only if the NAT rule
# that makes it real was actually installed.
echo "── port hopping reaches the client and the firewall"
rm -rf "$SB"; make_stubs; sandbox_script
out=$(sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 2>&1)
if grep -q '"ports": "20000-30000"' "$SB/etc/airport-tool/profile.json" \
   && grep -q 'mport=20000-30000' "$SB/etc/airport-tool/hysteria2.env" \
   && grep -q 'Port hopping: UDP 20000-30000' <<<"$out"; then
  echo "   ✓ range reached profile.json, the URI and the NAT setup"
else
  echo "   ✗ port hopping did not propagate"; fails=$((fails + 1))
fi

# The three firewalls spell a range differently and reject the other spellings.
# iptables wants a colon; handing it the firewalld form got the rule refused
# while the script cheerfully reported the port open.
if grep -q -- '--dport 20000:30000 -j ACCEPT' "$SB/iptables.log" \
   && grep -q -- '--dport 20000:30000 -j REDIRECT' "$SB/iptables.log" \
   && ! grep -q -- '20000-30000' "$SB/iptables.log" \
   && ! grep -qi 'Could not add an iptables rule' <<<"$out"; then
  echo "   ✓ iptables got the colon form, and accepted every rule"
else
  echo "   ✗ a firewall rule used the wrong range spelling"; fails=$((fails + 1))
fi

# The camouflage has to point somewhere else. Pointing it at this server's own
# domain makes Hysteria2 fetch from a TCP port it does not serve, so a prober
# gets an error — the one outcome masquerading exists to prevent.
# A comma-separated range reached every client and installed no NAT rule at all:
# this side only ever accepted a single `a-b` pair, while config-gen happily
# emitted lists. Every hop then aimed at a port with nothing behind it.
echo "── a comma-separated port range reaches both the client and the firewall"
rm -rf "$SB"; make_stubs; sandbox_script
out=$(sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-25000,30000-35000 2>&1)
if grep -q '"ports": "20000-25000,30000-35000"' "$SB/etc/airport-tool/profile.json" \
   && grep -q 'mport=20000-25000,30000-35000' "$SB/etc/airport-tool/hysteria2.env"; then
  echo "   ✓ the whole list reached profile.json and the URI"
else
  echo "   ✗ the comma-separated range did not propagate"
  grep -o '"ports": "[^"]*"' "$SB/etc/airport-tool/profile.json" | sed 's/^/     /'
  fails=$((fails + 1))
fi

# One NAT rule and one firewall opening per segment, each in the colon spelling
# iptables actually parses — the stub rejects anything else, as the real one does.
if grep -q -- '-t nat -A PREROUTING -p udp --dport 20000:25000 -j REDIRECT --to-ports 443' "$SB/iptables.log" \
   && grep -q -- '-t nat -A PREROUTING -p udp --dport 30000:35000 -j REDIRECT --to-ports 443' "$SB/iptables.log" \
   && grep -q -- '--dport 20000:25000 -j ACCEPT' "$SB/iptables.log" \
   && grep -q -- '--dport 30000:35000 -j ACCEPT' "$SB/iptables.log"; then
  echo "   ✓ both segments got a NAT rule and a firewall opening"
else
  echo "   ✗ the per-segment iptables rules are wrong:"
  grep -- '--dport' "$SB/iptables.log" | sed 's/^/     /'
  fails=$((fails + 1))
fi

# The two parsers have to accept exactly the same set. They used to disagree,
# which is the whole reason the case above was broken.
echo "── the shell and JS port-range parsers agree"
mismatch=0
# shellcheck disable=SC1090  # sourcing a slice of the script under test on purpose
eval "$(sed -n '/^normalize_hop_range()/,/^}/p' "$SRC")"
for v in "20000-30000" "20000:30000" "20000,30001-30002" "8443" "0-100" "1-70000" "abc" "20000-19000"; do
  if sh_out=$(normalize_hop_range "$v" 2>/dev/null); then sh_res="$sh_out"; else sh_res="REJECTED"; fi
  js_res=$(node -e "
    const C = require('$REPO_NODE/config-gen/lib/configs.js');
    const r = C.normalizePortRange(process.argv[1]);
    process.stdout.write(r || 'REJECTED');
  " "$v")
  if [[ "$sh_res" != "$js_res" ]]; then
    echo "   ✗ '$v': setup.sh says '$sh_res', config-gen says '$js_res'"
    mismatch=1
  fi
done
if [[ $mismatch -eq 0 ]]; then
  echo "   ✓ both accept and reject the same ranges"
else
  fails=$((fails + 1))
fi

# Hysteria2's whole reason for existing is Brutal, and Brutal is off unless the
# client declares a rate. Every profile this script wrote used to arrive without
# one, so every install silently ran the BBR fallback it was chosen to avoid.
echo "── the declared bandwidth reaches the client"
rm -rf "$SB"; make_stubs; sandbox_script
out=$(sb_run PROTOCOL=hysteria2 HY2_UP=50 HY2_DOWN=200 2>&1)
if grep -q '"up": 50' "$SB/etc/airport-tool/profile.json" \
   && grep -q '"down": 200' "$SB/etc/airport-tool/profile.json" \
   && grep -q 'up=50&upmbps=50&down=200&downmbps=200' "$SB/etc/airport-tool/hysteria2.env"; then
  echo "   ✓ both halves reached profile.json and the URI"
else
  echo "   ✗ the declared bandwidth did not propagate"
  grep -oE '"(up|down)": [0-9]*' "$SB/etc/airport-tool/profile.json" | sed 's/^/     /'
  fails=$((fails + 1))
fi

# A bare re-run must not throw the rate away — the same reuse rule as the port
# and the SNI above.
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
if grep -q '"up": 50' "$SB/etc/airport-tool/profile.json"; then
  echo "   ✓ survived a bare re-run"
else
  echo "   ✗ a re-run dropped the declared bandwidth"; fails=$((fails + 1))
fi

# Half a pair is not a rate, and a client that gets one silently falls back to
# BBR. Refusing says so while it can still be fixed.
rm -rf "$SB"; make_stubs; sandbox_script
out=$(sb_run PROTOCOL=hysteria2 HY2_UP=50 2>&1)
if grep -q 'have to be set together' <<<"$out"; then
  echo "   ✓ one half alone is refused"
else
  echo "   ✗ HY2_UP without HY2_DOWN was accepted"; fails=$((fails + 1))
fi
out=$(sb_run PROTOCOL=hysteria2 HY2_UP=fast HY2_DOWN=200 2>&1)
if grep -q 'whole number of Mbps' <<<"$out"; then
  echo "   ✓ a non-numeric rate is refused"
else
  echo "   ✗ a non-numeric HY2_UP was accepted"; fails=$((fails + 1))
fi

# The default is still "unset", and it has to say so rather than leave the
# reader assuming Brutal is on.
rm -rf "$SB"; make_stubs; sandbox_script
out=$(sb_run PROTOCOL=hysteria2 2>&1)
if grep -q '"up": 0' "$SB/etc/airport-tool/profile.json" \
   && grep -q 'fall back to BBR' <<<"$out"; then
  echo "   ✓ with no rate declared, the profile says 0 and the run warns"
else
  echo "   ✗ the undeclared case is wrong"; fails=$((fails + 1))
fi

echo "── the masquerade target is never this server"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=hysteria2 DOMAIN=proxy.example.com >/dev/null 2>&1
if grep -q 'url: https://www.bing.com/' "$SB/etc/hysteria/config.yaml" \
   && ! grep -q 'url: https://proxy.example.com/' "$SB/etc/hysteria/config.yaml"; then
  echo "   ✓ ACME mode masquerades as an external site, not itself"
else
  echo "   ✗ the masquerade points back at this server"; fails=$((fails + 1))
fi
out=$(sb_run PROTOCOL=hysteria2 FORCE=1 DOMAIN=proxy.example.com HY2_MASQUERADE=proxy.example.com 2>&1)
if grep -q "is this server's own domain" <<<"$out" \
   && grep -q 'url: https://www.bing.com/' "$SB/etc/hysteria/config.yaml"; then
  echo "   ✓ a self-referential HY2_MASQUERADE is caught and replaced"
else
  echo "   ✗ HY2_MASQUERADE was allowed to point at this server"; fails=$((fails + 1))
fi
out=$(sb_run PROTOCOL=hysteria2 FORCE=1 HY2_MASQUERADE=www.apple.com 2>&1)
if grep -q 'url: https://www.apple.com/' "$SB/etc/hysteria/config.yaml"; then
  echo "   ✓ a chosen masquerade target is used"
else
  echo "   ✗ HY2_MASQUERADE was ignored"; fails=$((fails + 1))
fi
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 >/dev/null 2>&1

# An unusable range must be dropped rather than advertised — a client told to
# hop across ports nothing listens on is worse off than one that never hopped.
out=$(sb_run PROTOCOL=hysteria2 FORCE=1 HY2_PORT_RANGE=not-a-range 2>&1)
if grep -q 'not a usable range' <<<"$out" && ! grep -q 'mport=' "$SB/etc/airport-tool/hysteria2.env"; then
  echo "   ✓ a malformed range is refused, not passed to clients"
else
  echo "   ✗ a malformed range leaked into the client URI"; fails=$((fails + 1))
fi

# Installing a second protocol used to truncate the first one's server.env,
# taking its keys with it — while printing "installing alongside it".
echo "── a second protocol does not clobber the first"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
reality_uuid=$(grep -o "REALITY_UUID='[^']*'" "$SB/etc/airport-tool/reality.env" || true)
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
reality_after=$(grep -o "REALITY_UUID='[^']*'" "$SB/etc/airport-tool/reality.env" 2>/dev/null || true)
if [[ -n "$reality_uuid" && "$reality_uuid" == "$reality_after" ]] \
   && [[ -f "$SB/etc/airport-tool/hysteria2.env" ]]; then
  echo "   ✓ both protocols keep their own state"
else
  echo "   ✗ before=$reality_uuid after=$reality_after"; fails=$((fails + 1))
fi

echo "── --show lists every installed protocol"
out=$(sb_flag --show 2>&1)
if grep -q 'reality' <<<"$out" && grep -q 'hysteria2' <<<"$out" && grep -q 'HY2_PASSWORD' <<<"$out"; then
  echo "   ✓ printed both"
else
  echo "   ✗ --show only knew about one protocol"; fails=$((fails + 1))
fi

# With two installed, an unqualified --uninstall has to refuse rather than pick.
echo "── uninstall removes one protocol, not its neighbour"
if sb_flag --uninstall >/dev/null 2>&1; then
  echo "   ✗ ambiguous --uninstall should have refused"; fails=$((fails + 1))
else
  echo "   ✓ refused to guess which one"
fi
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=hysteria2 bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if [[ -f "$SB/etc/airport-tool/reality.env" && ! -f "$SB/etc/airport-tool/hysteria2.env" ]]; then
  echo "   ✓ removed hysteria2 and left reality alone"
else
  echo "   ✗ uninstalling one protocol disturbed the other"; fails=$((fails + 1))
fi

# A pre-split install must survive the upgrade, not read as "nothing installed".
echo "── a legacy server.env is migrated, not ignored"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
mv "$SB/etc/airport-tool/reality.env" "$SB/etc/airport-tool/server.env"
legacy_uuid=$(grep -o "REALITY_UUID='[^']*'" "$SB/etc/airport-tool/server.env")
sb_run PROTOCOL=reality >/dev/null 2>&1
if [[ ! -f "$SB/etc/airport-tool/server.env" ]] \
   && [[ "$(grep -o "REALITY_UUID='[^']*'" "$SB/etc/airport-tool/reality.env")" == "$legacy_uuid" ]]; then
  echo "   ✓ migrated in place and kept the existing UUID"
else
  echo "   ✗ the legacy state file was not migrated"; fails=$((fails + 1))
fi

echo "── uninstall removes state"
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=reality bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if [[ -d "$SB/etc/airport-tool" ]]; then
  echo "   ✗ state directory survived"; fails=$((fails + 1))
else
  echo "   ✓ removed"
fi

# --show --json is what makes "set up the server, import it on the PC" one
# command instead of a file copy, so stdout has to be JSON and nothing else —
# including on a run where the state migration or a warning has something to say.
echo "── --show --json emits importable JSON on stdout alone"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
json=$(env PATH="$SB/bin:/usr/bin:/bin" bash "$SB/setup.sh" --show --json 2>/dev/null)
if node -e "
  const list = JSON.parse(process.argv[1]);
  const C = require('$REPO_NODE/config-gen/lib/configs.js');
  if (!Array.isArray(list) || list.length !== 2) throw new Error('expected 2 profiles, got ' + JSON.stringify(list).slice(0, 80));
  for (const raw of list) {
    const p = C.normalizeProfile(raw);
    const v = C.validateProfile(p);
    if (v.errors.length) throw new Error(p.protocol + ': ' + v.errors.join('; '));
  }
" "$json" 2>/dev/null; then
  echo "   ✓ two profiles, both accepted by config-gen"
else
  echo "   ✗ --show --json did not produce a clean, importable array"
  echo "$json" | head -5 | sed 's/^/     /'
  fails=$((fails + 1))
fi

echo "── --json without --show is refused"
if sb_flag --json >/dev/null 2>&1; then
  echo "   ✗ accepted --json on an install run"; fails=$((fails + 1))
else
  echo "   ✓ refused"
fi

# An IPv6-only VPS is a case the script already warns about, so the URI it
# prints has to survive it: an unbracketed literal makes the last colon read as
# part of the address rather than as the port separator.
echo "── an IPv6 address is bracketed in every URI"
rm -rf "$SB"; make_stubs; sandbox_script
cat > "$SB/bin/curl" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  case "$a" in
    *ifconfig.me*) echo "2001:db8::1"; exit 0 ;;
  esac
done
echo "true"
STUB
printf '#!/usr/bin/env bash\necho "2001:db8::1"\n' > "$SB/bin/hostname"
chmod +x "$SB"/bin/curl "$SB"/bin/hostname
v6_fails=0
for proto in reality hysteria2 tuic; do
  rm -rf "$SB/etc/airport-tool"
  sb_run PROTOCOL="$proto" >/dev/null 2>&1
  uri=$(grep -ho "_URI='[^']*'" "$SB/etc/airport-tool/${proto}.env" | head -1)
  if [[ "$uri" != *"@[2001:db8::1]:"* ]]; then
    echo "   ✗ ${proto}: $uri"; v6_fails=1
  fi
done
if [[ $v6_fails -eq 0 ]]; then
  echo "   ✓ reality, hysteria2 and tuic all bracket the literal"
else
  fails=$((fails + 1))
fi

rm -rf "$SB"
echo ""
if [[ $fails -eq 0 ]]; then echo "setup.sh: all cases passed"; else echo "setup.sh: $fails case(s) failed"; fi
exit $((fails > 0))
