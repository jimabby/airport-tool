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
SB="$REPO/server/.sandbox"
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
  printf '#!/usr/bin/env bash\n[[ "$1" == "-C" ]] && exit 1\nexit 0\n' > "$SB/bin/iptables"
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

rm -rf "$SB"
echo ""
if [[ $fails -eq 0 ]]; then echo "setup.sh: all cases passed"; else echo "setup.sh: $fails case(s) failed"; fi
exit $((fails > 0))
