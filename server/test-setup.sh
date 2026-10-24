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

# The checksum setup.sh pins for an architecture's v2ray-plugin tarball.
pinned_sha() {
  local arch="$1"
  case "$arch" in armv7*) arch='armv7\*' ;; armv6*) arch='armv6\*' ;; esac
  grep -A1 "^    ${arch}" "$SRC" | grep -o '[0-9a-f]\{64\}' | head -1
}

make_stubs() {
  mkdir -p "$SB/bin"

  # Anything that just needs to succeed quietly.
  for cmd in apt-get modprobe chown journalctl sysctl-noop; do
    printf '#!/usr/bin/env bash\nexit 0\n' > "$SB/bin/$cmd"
  done

  # Every unit is active unless a case lists it in $SB/inactive. Restarts are
  # logged so --upgrade can be checked for what it restarted.
  cat > "$SB/bin/systemctl" <<EOF
#!/usr/bin/env bash
echo "\$*" >> "${SB}/systemctl.log"
if [[ "\$1" == "is-active" ]]; then
  grep -qx "\${!#}" "${SB}/inactive" 2>/dev/null && exit 3
fi
exit 0
EOF

  # curl: answer the address probes, write a file for a download (-o), and for
  # an installer download a script that only logs how it was run.
  #
  # Address answers come from $SB/ip.<host>.<family> when a case writes one,
  # and otherwise only ifconfig.me over IPv4 answers (203.0.113.9). An echo
  # service that answers nothing usable is how the second-service fallback and
  # the address validation get exercised. Every URL asked for is logged.
  cat > "$SB/bin/curl" <<EOF
#!/usr/bin/env bash
out=""; prev=""; fam=4; url=""
for a in "\$@"; do
  [[ "\$prev" == "-o" ]] && out="\$a"
  case "\$a" in -6) fam=6 ;; -4) fam=4 ;; http*) url="\$a" ;; esac
  prev="\$a"
done
echo "\$url" >> "${SB}/curl.log"
h=""
case "\$url" in
  *ifconfig.me*)    h=ifconfig.me ;;
  *api.ipify.org*)  h=api.ipify.org ;;
  *api6.ipify.org*) h=api6.ipify.org ;;
esac
if [[ -n "\$h" ]]; then
  if [[ -f "${SB}/ip.\$h.\$fam" ]]; then cat "${SB}/ip.\$h.\$fam"; exit 0; fi
  [[ "\$h.\$fam" == "ifconfig.me.4" ]] && { echo "203.0.113.9"; exit 0; }
  exit 22
fi
if [[ -n "\$out" ]]; then
  case "\$out" in
    *-install.sh)
      printf '#!/usr/bin/env bash\necho "%s \$*" >> "%s/installers.log"\nexit 0\n' "\$(basename "\$out")" "${SB}" > "\$out" ;;
    *) echo "stub tarball" > "\$out" ;;
  esac
  exit 0
fi
echo "true"
EOF

  # The architecture the script believes it is on. STUB_ARCH picks it, so the
  # ARM download paths get exercised on an x86 runner.
  cat > "$SB/bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -m) echo "${STUB_ARCH:-x86_64}" ;;
  -r) echo "6.1.0-stub" ;;
  *)  echo "Linux" ;;
esac
EOF

  # tar and install used to be no-ops, which is how an install step naming a
  # file no release tarball contains shipped and failed on every server. These
  # behave like the real v2ray-plugin v1.3.2 assets: the member names are the
  # ones `tar -tzf` lists for each published tarball, a member that is not in
  # the archive is an error, and install refuses a source that does not exist.
  # Only the v2ray-plugin tarball is faked; --export-state/--import-state get
  # the real tar, since a round trip through it is the thing under test.
  cat > "$SB/bin/tar" <<'EOF'
#!/usr/bin/env bash
case " $* " in *v2ray-plugin.tar.gz*) ;; *) exec /usr/bin/tar "$@" ;; esac
dir="."; prev=""; want=()
for a in "$@"; do
  if [[ "$prev" == "-C" ]]; then dir="$a"
  elif [[ "$a" != -* && "$a" != *.tar.gz ]]; then want+=("$a"); fi
  prev="$a"
done
case "${STUB_ARCH:-x86_64}" in
  x86_64)        members="v2ray-plugin_linux_amd64" ;;
  aarch64|arm64) members="v2ray-plugin_linux_arm64" ;;
  armv*)         members="v2ray-plugin_linux_arm5 v2ray-plugin_linux_arm6 v2ray-plugin_linux_arm7" ;;
  *)             members="" ;;
esac
for w in "${want[@]}"; do
  [[ " $members " == *" $w "* ]] || { echo "tar: $w: Not found in archive" >&2; exit 2; }
done
for m in ${want[@]:-$members}; do printf 'stub binary\n' > "$dir/$m"; done
exit 0
EOF
  cat > "$SB/bin/install" <<'EOF'
#!/usr/bin/env bash
args=(); skip=0
for a in "$@"; do
  if [[ $skip -eq 1 ]]; then skip=0; continue; fi
  [[ "$a" == "-m" ]] && { skip=1; continue; }
  args+=("$a")
done
[[ -f "${args[0]}" ]] || { echo "install: cannot stat '${args[0]}': No such file or directory" >&2; exit 1; }
exit 0
EOF
  # sha256sum answers with whatever $SB/stub-sha holds — by default the hash
  # setup.sh pins for the stub architecture, so a case can swap in a wrong one.
  # An installer script answers with the hash setup.sh pins for it, unless
  # $SB/stub-installer-sha holds a different one (a tampered download).
  cat > "$SB/bin/sha256sum" <<EOF
#!/usr/bin/env bash
case "\$(basename "\$1")" in
  xray-install.sh)     var=XRAY_INSTALLER_SHA256 ;;
  hysteria-install.sh) var=HY2_INSTALLER_SHA256 ;;
  sing-box-install.sh) var=SINGBOX_INSTALLER_SHA256 ;;
  *) printf '%s  %s\n' "\$(cat "${SB}/stub-sha")" "\$1"; exit 0 ;;
esac
if [[ -f "${SB}/stub-installer-sha" ]]; then h=\$(cat "${SB}/stub-installer-sha")
else h=\$(grep -m1 "^\${var}=" "${SB}/setup.sh" | grep -o '[0-9a-f]\{64\}'); fi
printf '%s  %s\n' "\$h" "\$1"
EOF
  pinned_sha x86_64 > "$SB/stub-sha"

  # Xray's key generator. It changed its output in 2025 — "PrivateKey:" and
  # "Password (PublicKey):" instead of "Private key:" / "Public key:" — and the
  # stub only ever spoke the old one, so the parser that broke on every current
  # Xray kept passing here. The current format is the default; STUB_XRAY_FORMAT
  # =legacy keeps the old one covered for servers still running it.
  cat > "$SB/bin/xray" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  x25519)
    if [[ "${STUB_XRAY_FORMAT:-current}" == "legacy" ]]; then
      echo "Private key: PRIVKEYAAA"; echo "Public key: PUBKEYBBB"
    else
      echo "PrivateKey: PRIVKEYAAA"; echo "Password (PublicKey): PUBKEYBBB"; echo "Hash32: HASHCCC"
    fi ;;
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
# -S (list rules) prints whatever a case put in \$SB/iptables-S.
if [[ " \$* " == *" -S "* ]]; then cat "${SB}/iptables-S" 2>/dev/null; exit 0; fi
# Nothing exists in a fresh sandbox, so every check reports "not found" and the
# script takes the insert path — which is the path worth testing. --doctor
# cases create \$SB/iptables-present to make every check answer "yes".
[[ \$check -eq 1 && ! -f "${SB}/iptables-present" ]] && exit 1
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

  # chown changes nothing here (the sandbox is not root) but says what it was
  # asked, so a case can check which group a secret was handed to.
  printf '#!/usr/bin/env bash\necho "$*" >> "%s/chown.log"\nexit 0\n' "$SB" > "$SB/bin/chown"
  # certbot: "issue" a certificate for -d DOMAIN where the script looks for it.
  cat > "$SB/bin/certbot" <<EOF
#!/usr/bin/env bash
d=""; prev=""
for a in "\$@"; do [[ "\$prev" == "-d" ]] && d="\$a"; prev="\$a"; done
mkdir -p "${SB}/etc/letsencrypt/live/\$d"
echo "stub cert" > "${SB}/etc/letsencrypt/live/\$d/fullchain.pem"
echo "stub key"  > "${SB}/etc/letsencrypt/live/\$d/privkey.pem"
EOF

  # ss -lnt / -lnu: a header, then whatever $SB/ss-tcp / $SB/ss-udp hold.
  cat > "$SB/bin/ss" <<EOF
#!/usr/bin/env bash
echo "State  Recv-Q Send-Q Local Address:Port Peer Address:Port"
case "\$1" in *u*) cat "${SB}/ss-udp" 2>/dev/null ;; *) cat "${SB}/ss-tcp" 2>/dev/null ;; esac
exit 0
EOF
  # runuser -u USER -- CMD: runs CMD as us, unless USER is in \$SB/locked-out.
  cat > "$SB/bin/runuser" <<EOF
#!/usr/bin/env bash
user="\$2"; shift 3
grep -qx "\$user" "${SB}/locked-out" 2>/dev/null && exit 1
exec "\$@"
EOF

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
# No IPv4 answer at all (an address of the wrong family is not one), IPv6 only.
echo "2001:db8::1" > "$SB/ip.ifconfig.me.4"
echo "2001:db8::1" > "$SB/ip.ifconfig.me.6"
printf '#!/usr/bin/env bash\necho "2001:db8::1"\n' > "$SB/bin/hostname"
chmod +x "$SB"/bin/hostname
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

# ── Xray's key output, both spellings ───────────────────────────────────────
echo "── Reality parses the keypair from current and legacy Xray output"
for fmt in current legacy; do
  rm -rf "$SB"; make_stubs; sandbox_script
  out=$(sb_run PROTOCOL=reality STUB_XRAY_FORMAT="$fmt" 2>&1)
  if grep -q '"publicKey": "PUBKEYBBB"' "$SB/etc/airport-tool/profile.json" 2>/dev/null \
     && grep -rqs --include=config.json '"privateKey": "PRIVKEYAAA"' "$SB"; then
    echo "   ✓ ${fmt} format"
  else
    echo "   ✗ ${fmt} format was not parsed"; echo "$out" | tail -3 | sed 's/^/     /'
    fails=$((fails + 1))
  fi
done

# ── The v2ray-plugin download ───────────────────────────────────────────────
echo "── v2ray-plugin: the binary each release tarball actually contains"
for arch in x86_64 aarch64 armv7l armv6l; do
  rm -rf "$SB"; make_stubs; sandbox_script
  pinned_sha "$arch" > "$SB/stub-sha"
  if out=$(sb_run PROTOCOL=shadowsocks STUB_ARCH="$arch" 2>&1); then
    echo "   ✓ ${arch}"
  else
    echo "   ✗ ${arch}"; echo "$out" | grep -i 'error\|tar:\|install:' | tail -3 | sed 's/^/     /'
    fails=$((fails + 1))
  fi
done
rm -rf "$SB"; make_stubs; sandbox_script
echo "0000000000000000000000000000000000000000000000000000000000000000" > "$SB/stub-sha"
out=$(sb_run PROTOCOL=shadowsocks 2>&1)
if grep -q 'does not match its published checksum' <<<"$out" && [[ ! -f "$SB/etc/airport-tool/shadowsocks.env" ]]; then
  echo "   ✓ a download with the wrong checksum is refused before anything is installed"
else
  echo "   ✗ a tampered download was accepted"; fails=$((fails + 1))
fi

# ── Quoting what the caller chose ───────────────────────────────────────────
# A quote or backslash in a password used to produce a config.json the server
# could not parse; a colon or # changed what the Hysteria2 YAML meant.
echo "── passwords with quotes, backslashes and YAML syntax survive intact"
rm -rf "$SB"; make_stubs; sandbox_script
tricky='a"b\c'"'"'d: #e'
sb_run PROTOCOL=shadowsocks SS_PASSWORD="$tricky" >/dev/null 2>&1
ss_ok=$(node -e "
  const fs = require('fs');
  const want = process.argv[1];
  const a = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  const b = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
  process.stdout.write(a.password === want && b.password === want ? 'yes' : 'no: ' + a.password);
" "$tricky" "$(cd "$SB/etc/shadowsocks-libev" && { pwd -W 2>/dev/null || pwd; })/config.json" \
  "$(cd "$SB/etc/airport-tool" && { pwd -W 2>/dev/null || pwd; })/profile.json" 2>&1)
if [[ "$ss_ok" == "yes" ]]; then
  echo "   ✓ Shadowsocks config.json and profile.json both parse and carry it exactly"
else
  echo "   ✗ Shadowsocks: $ss_ok"; fails=$((fails + 1))
fi
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=hysteria2 HY2_PASSWORD="$tricky" >/dev/null 2>&1
if grep -qF "password: 'a\"b\\c''d: #e'" "$SB/etc/hysteria/config.yaml"; then
  echo "   ✓ Hysteria2 YAML single-quotes it"
else
  echo "   ✗ Hysteria2 YAML:"; grep -n 'password' "$SB/etc/hysteria/config.yaml" | sed 's/^/     /'
  fails=$((fails + 1))
fi

# ── Refusing what cannot work ───────────────────────────────────────────────
echo "── inputs that cannot produce a working server are refused up front"
refused() {
  local label="$1" pattern="$2"; shift 2
  rm -rf "$SB"; make_stubs; sandbox_script
  local out
  if out=$(sb_run "$@" 2>&1); then
    echo "   ✗ ${label}: accepted"; fails=$((fails + 1))
  elif grep -q -- "$pattern" <<<"$out"; then
    echo "   ✓ ${label}"
  else
    echo "   ✗ ${label}: refused, but not with '${pattern}'"; echo "$out" | tail -2 | sed 's/^/     /'
    fails=$((fails + 1))
  fi
}
refused "TLS mode without a domain" "needs DOMAIN" PROTOCOL=shadowsocks V2RAY_PLUGIN_MODE=tls
refused "a Shadowsocks 2022 key of the wrong length" "is not a 2022-blake3-aes-256-gcm key" \
  PROTOCOL=shadowsocks SS_METHOD=2022-blake3-aes-256-gcm SS_PASSWORD=not-a-key
refused "Shadowsocks 2022 with the v2ray-plugin TLS mode" "runs without a plugin" \
  PROTOCOL=shadowsocks SS_METHOD=2022-blake3-aes-128-gcm V2RAY_PLUGIN_MODE=tls DOMAIN=a.example.com
refused "a 2022 cipher name that does not exist" "is not a Shadowsocks 2022 cipher" \
  PROTOCOL=shadowsocks SS_METHOD=2022-blake3-nope
refused "a port that is not a number" "is not a port" PROTOCOL=reality REALITY_PORT=abc
refused "an SNI that is not a hostname" "is not a hostname" PROTOCOL=reality 'REALITY_SNI=evil.com", "x'
refused "a password with a newline in it" "control character" PROTOCOL=hysteria2 "HY2_PASSWORD=$(printf 'a\nb')"

# ── Two protocols, one port ─────────────────────────────────────────────────
echo "── a second protocol cannot take a port the first one holds"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
out=$(sb_run PROTOCOL=tuic 2>&1)
if grep -q 'already uses' <<<"$out" && [[ ! -f "$SB/etc/airport-tool/tuic.env" ]]; then
  echo "   ✓ TUIC on Hysteria2's 443/udp is refused"
else
  echo "   ✗ TUIC was installed on top of Hysteria2's port"; fails=$((fails + 1))
fi
if sb_run PROTOCOL=tuic TUIC_PORT=8443 >/dev/null 2>&1 && [[ -f "$SB/etc/airport-tool/tuic.env" ]]; then
  echo "   ✓ on another port it installs"
else
  echo "   ✗ TUIC on 8443 was refused"; fails=$((fails + 1))
fi
# Reality on 443/tcp does not collide with Hysteria2 on 443/udp.
if sb_run PROTOCOL=reality >/dev/null 2>&1 && [[ -f "$SB/etc/airport-tool/reality.env" ]]; then
  echo "   ✓ the same number over TCP is not a conflict"
else
  echo "   ✗ Reality 443/tcp was refused next to Hysteria2 443/udp"; fails=$((fails + 1))
fi
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=tuic TUIC_PORT=25000 >/dev/null 2>&1
out=$(sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 2>&1)
if grep -q 'redirect would swallow' <<<"$out"; then
  echo "   ✓ a hop range that would swallow TUIC's port is refused"
else
  echo "   ✗ the hop range was allowed over TUIC's port"; fails=$((fails + 1))
fi

# ── Uninstall leaves a neighbour's firewall rule alone ──────────────────────
# Hysteria2 and TUIC used to close their port over TCP too, which with the
# defaults deleted the 443/tcp rule Reality depends on.
echo "── uninstalling Hysteria2 keeps Reality's 443/tcp open"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
: > "$SB/iptables.log"
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=hysteria2 bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if grep -q -- '-D INPUT -p udp --dport 443 -j ACCEPT' "$SB/iptables.log" \
   && ! grep -q -- '-D INPUT -p tcp --dport 443' "$SB/iptables.log"; then
  echo "   ✓ only 443/udp was closed"
else
  echo "   ✗ the uninstall touched TCP:"; grep -- '-D INPUT' "$SB/iptables.log" | sed 's/^/     /'
  fails=$((fails + 1))
fi

# ── Shadowsocks 2022 on sing-box ────────────────────────────────────────────
# shadowsocks-libev has no 2022 support, so those ciphers used to be refused
# outright. They are served by sing-box under their own unit now.
echo "── Shadowsocks 2022 installs on sing-box, with a key of the right length"
for method in 2022-blake3-aes-128-gcm 2022-blake3-aes-256-gcm; do
  run_case "shadowsocks ${method}" PROTOCOL=shadowsocks SS_METHOD="$method"
done
rm -rf "$SB"; make_stubs; sandbox_script
: > "$SB/iptables.log"
sb_run PROTOCOL=shadowsocks SS_METHOD=2022-blake3-aes-256-gcm >/dev/null 2>&1
pj="$SB/etc/airport-tool/profile.json"
if grep -q '"plugin": ""' "$pj" && grep -q '"method": "2022-blake3-aes-256-gcm"' "$pj" \
   && [[ -f "$SB/etc/systemd/system/airport-ss2022.service" ]] \
   && grep -q '"type": "shadowsocks"' "$SB/etc/airport-ss2022/config.json" \
   && grep -q -- '-p udp --dport 8388 -j ACCEPT' "$SB/iptables.log" \
   && grep -q -- '-p tcp --dport 8388 -j ACCEPT' "$SB/iptables.log"; then
  echo "   ✓ no plugin, its own unit and config, TCP and UDP both opened"
else
  echo "   ✗ the 2022 install is not what it should be"; fails=$((fails + 1))
fi
key1=$(grep -o '"password": "[^"]*"' "$pj")
sb_run PROTOCOL=shadowsocks >/dev/null 2>&1
if [[ "$(grep -o '"password": "[^"]*"' "$pj")" == "$key1" ]]; then
  echo "   ✓ a bare re-run keeps the cipher and the key"
else
  echo "   ✗ a re-run changed the 2022 key"; fails=$((fails + 1))
fi
# TUIC and Shadowsocks 2022 share the executable, not the service/config.
echo "-- removing TUIC preserves the Shadowsocks 2022 executable"
sb_run PROTOCOL=tuic TUIC_PORT=8443 >/dev/null 2>&1
printf '#!/usr/bin/env bash\nexit 0\n' > "$SB/bin/sing-box"
chmod +x "$SB/bin/sing-box"
cat > "$SB/bin/apt-get" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "$SB/apt-removal.log"
STUB
chmod +x "$SB/bin/apt-get"
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=tuic bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if [[ -f "$SB/bin/sing-box" && -f "$SB/etc/systemd/system/airport-ss2022.service" ]] \
   && ! grep -q 'remove.*sing-box' "$SB/apt-removal.log" 2>/dev/null; then
  echo "   PASS: the executable, package and Shadowsocks unit survive"
else
  echo "   FAIL: removing TUIC broke Shadowsocks 2022"; fails=$((fails + 1))
fi

# A libev passphrase is not a 2022 key, so switching ciphers must mint one.
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=shadowsocks SS_PASSWORD=plainpass >/dev/null 2>&1
out=$(sb_run PROTOCOL=shadowsocks SS_METHOD=2022-blake3-aes-128-gcm 2>&1)
if grep -q 'not a 2022-blake3-aes-128-gcm key' <<<"$out" && ! grep -q 'plainpass' "$pj"; then
  echo "   ✓ switching from libev to 2022 replaces the passphrase with a key, and says so"
else
  echo "   ✗ the libev passphrase was carried into a 2022 install"; fails=$((fails + 1))
fi
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=shadowsocks bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if [[ ! -f "$SB/etc/systemd/system/airport-ss2022.service" && ! -d "$SB/etc/airport-ss2022" ]]; then
  echo "   ✓ uninstall removes the 2022 unit and config"
else
  echo "   ✗ the 2022 backend survived --uninstall"; fails=$((fails + 1))
fi

# ── shadowsocks-libev runs as nobody ────────────────────────────────────────
# It could neither bind a port below 1024 nor read its root-only config.
echo "── shadowsocks-libev can bind a low port and read its own config"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=shadowsocks SS_PORT=443 >/dev/null 2>&1
unit="$SB/etc/systemd/system/shadowsocks-libev.service"
mode=$(stat -c '%a' "$SB/etc/shadowsocks-libev/config.json" 2>/dev/null || echo '?')
if grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE' "$unit" && grep -q 'nobody_group_owns /etc' "$SRC"; then
  echo "   ✓ the unit grants CAP_NET_BIND_SERVICE, and the config is handed to nobody's group (mode ${mode})"
else
  echo "   ✗ the unit or the config ownership is wrong"; fails=$((fails + 1))
fi

# ── Port hopping survives a reboot without iptables-persistent ──────────────
echo "── the hop redirect gets its own boot unit, and ufw is never removed for it"
rm -rf "$SB"; make_stubs; sandbox_script
printf '#!/usr/bin/env bash\necho "$*" >> "%s/apt.log"\nexit 0\n' "$SB" > "$SB/bin/apt-get"
# ufw installed but inactive: the iptables path runs, and the conflict matters.
printf '#!/usr/bin/env bash\n[[ "$1" == "status" ]] && echo "Status: inactive"\nexit 0\n' > "$SB/bin/ufw"
chmod +x "$SB/bin/apt-get" "$SB/bin/ufw"
sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 >/dev/null 2>&1
if [[ -f "$SB/etc/systemd/system/airport-hy2-hop.service" ]] \
   && grep -q -- '--dport 20000:30000 -j REDIRECT --to-ports 443' "$SB/etc/airport-tool/hy2-hop.sh"; then
  echo "   ✓ a oneshot unit re-applies the redirect at boot"
else
  echo "   ✗ the hop redirect has no boot unit"; fails=$((fails + 1))
fi
if ! grep -q 'iptables-persistent' "$SB/apt.log" 2>/dev/null; then
  echo "   ✓ iptables-persistent was not installed next to ufw (apt would remove ufw for it)"
else
  echo "   ✗ iptables-persistent was installed on a ufw box"; fails=$((fails + 1))
fi
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=hysteria2 bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if [[ ! -f "$SB/etc/systemd/system/airport-hy2-hop.service" ]]; then
  echo "   ✓ uninstall removes the unit"
else
  echo "   ✗ the hop unit survived --uninstall"; fails=$((fails + 1))
fi

# ── Installers are pinned ───────────────────────────────────────────────────
echo "── every installer is asked for the pinned release"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
sb_run PROTOCOL=tuic TUIC_PORT=8443 >/dev/null 2>&1
log=$(cat "$SB/installers.log" 2>/dev/null)
if grep -q 'xray-install.sh install --version v[0-9]' <<<"$log" \
   && grep -q 'hysteria-install.sh --version v[0-9]' <<<"$log" \
   && grep -q 'sing-box-install.sh --version [0-9]' <<<"$log"; then
  echo "   ✓ Xray, Hysteria2 and sing-box all got --version"
else
  echo "   ✗ an installer ran unpinned:"; echo "$log" | sed 's/^/     /'; fails=$((fails + 1))
fi
: > "$SB/installers.log"
sb_run PROTOCOL=reality FORCE=1 XRAY_VERSION=latest >/dev/null 2>&1
if grep -q 'xray-install.sh install$' "$SB/installers.log"; then
  echo "   ✓ =latest opts back into the newest release"
else
  echo "   ✗ XRAY_VERSION=latest still pinned:"; sed 's/^/     /' "$SB/installers.log"; fails=$((fails + 1))
fi

# The installer *scripts* are pinned too: fetched from a commit, not a branch
# or a redirect, and checked before they run. They used to be piped from
# raw/main, get.hy2.sh and sing-box.app straight into a root shell.
echo "── installer scripts come from pinned commits and are checksummed"
if grep -qE 'raw\.githubusercontent\.com/XTLS/Xray-install/[0-9a-f]{40}/install-release\.sh' "$SB/curl.log" \
   && grep -qE 'raw\.githubusercontent\.com/HyNetworks/hysteria/[0-9a-f]{40}/scripts/install_server\.sh' "$SB/curl.log" \
   && grep -qE 'raw\.githubusercontent\.com/SagerNet/sing-box/[0-9a-f]{40}/docs/installation/tools/install\.sh' "$SB/curl.log" \
   && ! grep -qE 'raw/main|get\.hy2\.sh|sing-box\.app' "$SB/curl.log" \
   && ! grep -vE '^[[:space:]]*#' "$SRC" | grep -qE 'bash <\(curl|bash -c "\$\(curl'; then
  echo "   ✓ all three from a commit SHA, none from a moving URL or a pipe"
else
  echo "   ✗ an installer came from a moving URL:"; sort -u "$SB/curl.log" | sed 's/^/     /'; fails=$((fails + 1))
fi
rm -rf "$SB"; make_stubs; sandbox_script
echo "0000000000000000000000000000000000000000000000000000000000000000" > "$SB/stub-installer-sha"
out=$(sb_run PROTOCOL=reality 2>&1)
if grep -q 'does not match its pinned checksum' <<<"$out" && [[ ! -s "$SB/installers.log" ]] \
   && [[ ! -f "$SB/etc/airport-tool/reality.env" ]]; then
  echo "   ✓ a tampered installer is refused before it runs"
else
  echo "   ✗ a tampered installer ran:"; echo "$out" | tail -3 | sed 's/^/     /'; fails=$((fails + 1))
fi
out=$(sb_run PROTOCOL=reality ALLOW_UNPINNED_INSTALLERS=1 2>&1)
if grep -q 'ALLOW_UNPINNED_INSTALLERS=1' <<<"$out" && grep -q 'Xray-install/raw/main' "$SB/curl.log" \
   && [[ -f "$SB/etc/airport-tool/reality.env" ]]; then
  echo "   ✓ ALLOW_UNPINNED_INSTALLERS=1 is the explicit, loud way out"
else
  echo "   ✗ ALLOW_UNPINNED_INSTALLERS=1 did not work"; fails=$((fails + 1))
fi
# Uninstall uses the same pinned script — it used to fetch raw/main to remove.
rm -f "$SB/stub-installer-sha"; : > "$SB/curl.log"; : > "$SB/installers.log"
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=reality bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if grep -q 'xray-install.sh remove --purge' "$SB/installers.log" && ! grep -q 'raw/main' "$SB/curl.log"; then
  echo "   ✓ --uninstall removes Xray with the pinned installer"
else
  echo "   ✗ --uninstall used an unpinned installer"; sed 's/^/     /' "$SB/curl.log"; fails=$((fails + 1))
fi

# ── Moving a port closes the old one ────────────────────────────────────────
# close_port was only ever called by --uninstall, so a re-run with a new port
# opened it and left the old one open for good.
echo "── a re-run on a new port closes the old one"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=tuic TUIC_PORT=8443 >/dev/null 2>&1
sb_run PROTOCOL=shadowsocks SS_PASSWORD=pw >/dev/null 2>&1
: > "$SB/iptables.log"
sb_run PROTOCOL=reality REALITY_PORT=9443 >/dev/null 2>&1
sb_run PROTOCOL=tuic TUIC_PORT=9443 >/dev/null 2>&1
sb_run PROTOCOL=shadowsocks SS_PORT=8444 >/dev/null 2>&1
if grep -q -- '-D INPUT -p tcp --dport 443 -j ACCEPT' "$SB/iptables.log" \
   && grep -q -- '-D INPUT -p udp --dport 8443 -j ACCEPT' "$SB/iptables.log" \
   && grep -q -- '-D INPUT -p tcp --dport 8388 -j ACCEPT' "$SB/iptables.log" \
   && ! grep -q -- '-D INPUT -p udp --dport 443' "$SB/iptables.log" \
   && ! grep -q -- '-D INPUT -p tcp --dport 8443' "$SB/iptables.log"; then
  echo "   ✓ Reality's old 443/tcp, TUIC's old 8443/udp and Shadowsocks' old 8388/tcp were closed — each over its own transport only"
else
  echo "   ✗ the old ports were not closed (or the wrong transport was):"
  grep -- '-D INPUT' "$SB/iptables.log" | sed 's/^/     /'; fails=$((fails + 1))
fi
: > "$SB/iptables.log"
sb_run PROTOCOL=reality >/dev/null 2>&1
if ! grep -q -- '-D INPUT' "$SB/iptables.log"; then
  echo "   ✓ a bare re-run closes nothing"
else
  echo "   ✗ a bare re-run closed a port:"; grep -- '-D INPUT' "$SB/iptables.log" | sed 's/^/     /'; fails=$((fails + 1))
fi
# 22/tcp is the one port this script must never close on anyone's behalf.
: > "$SB/iptables.log"
sb_run PROTOCOL=reality REALITY_PORT=22 >/dev/null 2>&1
sb_run PROTOCOL=reality REALITY_PORT=9443 >/dev/null 2>&1
if ! grep -q -- '-D INPUT -p tcp --dport 22 ' "$SB/iptables.log"; then
  echo "   ✓ moving off 22/tcp leaves ssh open"
else
  echo "   ✗ moving off 22 closed ssh"; fails=$((fails + 1))
fi

# ── Hop redirect follows the port and the range ────────────────────────────
# PREROUTING takes the first match, so an old REDIRECT left in front of the
# new one kept sending every hop to the old port.
echo "── re-running Hysteria2 with a new port or range replaces the old redirect"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 >/dev/null 2>&1
: > "$SB/iptables.log"
sb_run PROTOCOL=hysteria2 HY2_PORT=8443 >/dev/null 2>&1
if grep -q -- '-t nat -D PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 443' "$SB/iptables.log" \
   && grep -q -- '-t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 8443' "$SB/iptables.log" \
   && grep -q -- '--to-ports 8443' "$SB/etc/airport-tool/hy2-hop.sh" \
   && ! grep -q -- '--to-ports 443 ' "$SB/etc/airport-tool/hy2-hop.sh" \
   && grep -q -- '-D INPUT -p udp --dport 443 -j ACCEPT' "$SB/iptables.log"; then
  echo "   ✓ a new HY2_PORT removes the redirect to the old one, and the boot unit follows"
else
  echo "   ✗ the old redirect survived a port change:"; grep -- 'nat' "$SB/iptables.log" | sed 's/^/     /'; fails=$((fails + 1))
fi
: > "$SB/iptables.log"
sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=40000-41000 >/dev/null 2>&1
if grep -q -- '-t nat -D PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-ports 8443' "$SB/iptables.log" \
   && grep -q -- '-D INPUT -p udp --dport 20000:30000 -j ACCEPT' "$SB/iptables.log" \
   && grep -q -- '--dport 40000:41000' "$SB/etc/airport-tool/hy2-hop.sh" \
   && ! grep -q -- '20000:30000' "$SB/etc/airport-tool/hy2-hop.sh"; then
  echo "   ✓ a new range removes the old range's redirect and firewall opening"
else
  echo "   ✗ the old range survived:"; grep -- '20000' "$SB/iptables.log" | sed 's/^/     /'; fails=$((fails + 1))
fi
: > "$SB/iptables.log"
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
if ! grep -q -- '-t nat -D' "$SB/iptables.log"; then
  echo "   ✓ an unchanged range and port are left alone"
else
  echo "   ✗ a bare re-run tore the redirect down"; fails=$((fails + 1))
fi

# ── Shadowsocks: no stray 443, and 80 handed back ──────────────────────────
echo "── Shadowsocks TLS mode opens 80 for ACME but not 443, and gives 80 back"
rm -rf "$SB"; make_stubs; sandbox_script
: > "$SB/iptables.log"
sb_run PROTOCOL=shadowsocks V2RAY_PLUGIN_MODE=tls DOMAIN=ss.example.com SS_PASSWORD=pw >/dev/null 2>&1
if grep -q -- '-I INPUT 1 -p tcp --dport 80 -j ACCEPT' "$SB/iptables.log" \
   && ! grep -q -- '-p tcp --dport 443 -j ACCEPT' "$SB/iptables.log" \
   && grep -q "ACME_PORT80='1'" "$SB/etc/airport-tool/shadowsocks.env"; then
  echo "   ✓ 80/tcp opened and recorded; 443/tcp — which nothing listens on — not opened"
else
  echo "   ✗ the TLS-mode firewall openings are wrong:"; grep -- '-I INPUT' "$SB/iptables.log" | sed 's/^/     /'; fails=$((fails + 1))
fi
# TUIC with a domain needs 80 too; removing Shadowsocks must leave it for TUIC.
sb_run PROTOCOL=tuic TUIC_PORT=8443 DOMAIN=tuic.example.com >/dev/null 2>&1
: > "$SB/iptables.log"
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=shadowsocks bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if ! grep -q -- '-D INPUT -p tcp --dport 80 ' "$SB/iptables.log"; then
  echo "   ✓ uninstalling Shadowsocks keeps 80/tcp while TUIC still renews through it"
else
  echo "   ✗ 80/tcp was closed under TUIC"; fails=$((fails + 1))
fi
env PATH="$SB/bin:/usr/bin:/bin" PROTOCOL=tuic bash "$SB/setup.sh" --uninstall >/dev/null 2>&1
if grep -q -- '-D INPUT -p tcp --dport 80 -j ACCEPT' "$SB/iptables.log"; then
  echo "   ✓ the last ACME user's uninstall closes 80/tcp"
else
  echo "   ✗ 80/tcp was never closed"; fails=$((fails + 1))
fi
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=shadowsocks V2RAY_PLUGIN_MODE=tls DOMAIN=ss.example.com SS_PASSWORD=pw >/dev/null 2>&1
: > "$SB/iptables.log"
sb_run PROTOCOL=shadowsocks V2RAY_PLUGIN_MODE=websocket >/dev/null 2>&1
if grep -q -- '-D INPUT -p tcp --dport 80 -j ACCEPT' "$SB/iptables.log" \
   && grep -q "ACME_PORT80='0'" "$SB/etc/airport-tool/shadowsocks.env"; then
  echo "   ✓ switching TLS mode off hands 80/tcp back"
else
  echo "   ✗ 80/tcp stayed open after leaving TLS mode"; fails=$((fails + 1))
fi

echo "── switching Shadowsocks 2022 back to a libev cipher closes its UDP opening"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=shadowsocks SS_METHOD=2022-blake3-aes-256-gcm >/dev/null 2>&1
: > "$SB/iptables.log"
sb_run PROTOCOL=shadowsocks SS_METHOD=chacha20-ietf-poly1305 SS_PASSWORD=plain >/dev/null 2>&1
if grep -q -- '-D INPUT -p udp --dport 8388 -j ACCEPT' "$SB/iptables.log" \
   && ! grep -q -- '-D INPUT -p tcp --dport 8388' "$SB/iptables.log"; then
  echo "   ✓ 8388/udp closed, 8388/tcp kept"
else
  echo "   ✗ the 2022 backend's UDP opening survived:"; grep -- '-D INPUT' "$SB/iptables.log" | sed 's/^/     /'; fails=$((fails + 1))
fi

# ── The server address ─────────────────────────────────────────────────────
# An unvalidated probe answer — an error page, a portal — used to be written
# into every URI and profile.json as the "address".
echo "── the server address is validated before it reaches a client link"
rm -rf "$SB"; make_stubs; sandbox_script
echo "<html>rate limited</html>" > "$SB/ip.ifconfig.me.4"
echo "198.51.100.7" > "$SB/ip.api.ipify.org.4"
sb_run PROTOCOL=reality >/dev/null 2>&1
if grep -q '"server": "198.51.100.7"' "$SB/etc/airport-tool/profile.json"; then
  echo "   ✓ a garbage answer is discarded and the second service used"
else
  echo "   ✗ $(grep -o '"server": "[^"]*"' "$SB/etc/airport-tool/profile.json" 2>/dev/null)"; fails=$((fails + 1))
fi
rm -rf "$SB"; make_stubs; sandbox_script
echo "<html>" > "$SB/ip.ifconfig.me.4"
printf '#!/usr/bin/env bash\necho "10.0.0.5 fd00::5"\n' > "$SB/bin/hostname"
out=$(sb_run PROTOCOL=reality 2>&1)
if grep -q 'is a private one' <<<"$out" && grep -q 'SERVER_IP=<public address>' <<<"$out"; then
  echo "   ✓ a private hostname -I fallback is warned about, naming SERVER_IP"
else
  echo "   ✗ the private fallback went by silently"; fails=$((fails + 1))
fi
printf '#!/usr/bin/env bash\necho "not-an-address"\n' > "$SB/bin/hostname"
rm -rf "$SB/etc/airport-tool"
out=$(sb_run PROTOCOL=reality 2>&1)
if grep -q 'Could not determine' <<<"$out" && [[ ! -f "$SB/etc/airport-tool/reality.env" ]]; then
  echo "   ✓ with nothing valid anywhere it stops, writing nothing"
else
  echo "   ✗ an unvalidated address was used"; fails=$((fails + 1))
fi
refused "a SERVER_IP that is not an address" "is not an IPv4 or IPv6 address" PROTOCOL=reality 'SERVER_IP=1.2.3.4"x'
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality SERVER_IP=198.51.100.20 >/dev/null 2>&1
if grep -q '"server": "198.51.100.20"' "$SB/etc/airport-tool/profile.json" && ! grep -q 'ifconfig' "$SB/curl.log"; then
  echo "   ✓ SERVER_IP=… is used as given, with no probe"
else
  echo "   ✗ SERVER_IP was ignored"; fails=$((fails + 1))
fi

# ── Xray's config goes to the group its unit runs as ───────────────────────
echo "── the Xray config is readable by the account Xray-install runs it as"
rm -rf "$SB"; make_stubs; sandbox_script
printf '[Service]\nUser=xray\nGroup=xray\n' > "$SB/etc/systemd/system/xray.service"
sb_run PROTOCOL=reality >/dev/null 2>&1
if grep -q 'root:xray .*/xray/config.json' "$SB/chown.log"; then
  echo "   ✓ handed to group xray (not nogroup, which the xray user cannot read)"
else
  echo "   ✗ chown calls:"; sed 's/^/     /' "$SB/chown.log"; fails=$((fails + 1))
fi

echo "── a re-run keeps the self-signed certificate; FORCE=1 replaces it"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
c1=$(md5sum < "$SB/etc/hysteria/server.crt")
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
c2=$(md5sum < "$SB/etc/hysteria/server.crt")
sb_run PROTOCOL=hysteria2 FORCE=1 >/dev/null 2>&1
c3=$(md5sum < "$SB/etc/hysteria/server.crt")
if [[ "$c1" == "$c2" && "$c1" != "$c3" ]]; then
  echo "   ✓ same certificate across a re-run, a new one under FORCE=1"
else
  echo "   ✗ c1=$c1 c2=$c2 c3=$c3"; fails=$((fails + 1))
fi

# ── --doctor ────────────────────────────────────────────────────────────────
echo "── --doctor reports a healthy install, and changes nothing"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 >/dev/null 2>&1
touch "$SB/iptables-present"
echo "LISTEN 0 4096 [::]:443 [::]:*" > "$SB/ss-tcp"
echo "UNCONN 0 0 *:443 *:*" > "$SB/ss-udp"
echo "-A PREROUTING -p udp -m udp --dport 20000:30000 -j REDIRECT --to-ports 443" > "$SB/iptables-S"
snap() { find "$SB/etc" -type f -exec md5sum {} + | sort; }
# The report is coloured; the assertions read the words.
strip_ansi() { sed $'s/\033\\[[0-9;]*m//g'; }
before=$(snap); : > "$SB/iptables.log"
out=$(sb_flag --doctor 2>&1 | strip_ansi); rc=${PIPESTATUS[0]}
after=$(snap)
if [[ $rc -eq 0 ]] && ! grep -q '✗' <<<"$out" \
   && grep -q '✓ service xray is active' <<<"$out" \
   && grep -q '✓ listening on 443/udp' <<<"$out" \
   && grep -q '✓ hop redirect udp 20000-30000 → 443' <<<"$out" \
   && grep -qE '✓ certificate .*server.crt valid for [0-9]+ more day' <<<"$out" \
   && grep -q 'config.json is readable by xray' <<<"$out"; then
  echo "   ✓ every check passes and it exits 0"
else
  echo "   ✗ rc=$rc"; echo "$out" | grep -E '✗|ERROR' | sed 's/^/     /'; fails=$((fails + 1))
fi
if [[ "$before" == "$after" ]] && ! grep -qE -- ' -(A|I|D) ' "$SB/iptables.log"; then
  echo "   ✓ read-only: no file and no firewall rule changed"
else
  echo "   ✗ --doctor changed something"; fails=$((fails + 1))
fi
echo "xray" > "$SB/inactive"
rm -f "$SB/iptables-present"
: > "$SB/ss-udp"
echo "-A PREROUTING -p udp -m udp --dport 20000:30000 -j REDIRECT --to-ports 8443" >> "$SB/iptables-S"
printf '[Service]\nUser=xray\n' > "$SB/etc/systemd/system/xray.service"
echo "xray" > "$SB/locked-out"
# Git Bash would otherwise rewrite "/CN=…" into a Windows path (no-op elsewhere).
MSYS2_ARG_CONV_EXCL="/CN" openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$SB/k.pem" \
  -out "$SB/etc/hysteria/server.crt" -subj "/CN=www.bing.com" -days 5 >/dev/null 2>&1
out=$(sb_flag --doctor 2>&1 | strip_ansi); rc=${PIPESTATUS[0]}
if [[ $rc -ne 0 ]] \
   && grep -q '✗ service xray is not active' <<<"$out" \
   && grep -q '✗ nothing is listening on 443/udp' <<<"$out" \
   && grep -q '✗ firewall (iptables) has no rule for 443/tcp' <<<"$out" \
   && grep -q '✗ hop redirect udp 20000-30000 → 443 is missing' <<<"$out" \
   && grep -q '✗ stale hop redirect udp 20000-30000 → 8443' <<<"$out" \
   && grep -qE '✗ certificate .*expires in [0-9] day' <<<"$out" \
   && grep -q "✗ .*config.json is not readable by xray's user" <<<"$out"; then
  echo "   ✓ a dead service, a closed port, a missing and a stale redirect, an expiring cert and an unreadable config are all caught, exit ${rc}"
else
  echo "   ✗ rc=$rc"; echo "$out" | sed 's/^/     /'; fails=$((fails + 1))
fi

# ── --upgrade ───────────────────────────────────────────────────────────────
echo "── --upgrade reinstalls the binaries and leaves keys, config and firewall alone"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=hysteria2 >/dev/null 2>&1
sb_run PROTOCOL=tuic TUIC_PORT=8443 >/dev/null 2>&1
before=$(snap); : > "$SB/iptables.log"; : > "$SB/installers.log"; : > "$SB/systemctl.log"
out=$(sb_flag --upgrade 2>&1); rc=$?
after=$(snap)
if [[ $rc -eq 0 ]] \
   && grep -q 'xray-install.sh install --force --version v[0-9]' "$SB/installers.log" \
   && grep -q 'hysteria-install.sh --force --version v[0-9]' "$SB/installers.log" \
   && grep -q 'sing-box-install.sh --version [0-9]' "$SB/installers.log" \
   && grep -q 'restart xray' "$SB/systemctl.log" && grep -q 'restart hysteria-server' "$SB/systemctl.log" \
   && grep -q 'restart sing-box' "$SB/systemctl.log"; then
  echo "   ✓ all three pinned installers re-ran and their services restarted"
else
  echo "   ✗ rc=$rc"; echo "$out" | tail -5 | sed 's/^/     /'; sed 's/^/     /' "$SB/installers.log"; fails=$((fails + 1))
fi
if [[ "$before" == "$after" && ! -s "$SB/iptables.log" ]]; then
  echo "   ✓ no state, config or key file and no firewall rule changed"
else
  echo "   ✗ --upgrade touched more than the binaries"; diff <(echo "$before") <(echo "$after") | head -5 | sed 's/^/     /'
  fails=$((fails + 1))
fi

# ── --export-state / --import-state ────────────────────────────────────────
echo "── --export-state then --import-state on a new box keeps every credential"
rm -rf "$SB"; make_stubs; sandbox_script
sb_run PROTOCOL=reality >/dev/null 2>&1
sb_run PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 >/dev/null 2>&1
r_env=$(grep -E "^REALITY_(UUID|PUBLIC_KEY|PRIVATE_KEY|SHORT_ID)=" "$SB/etc/airport-tool/reality.env")
h_env=$(grep -E "^HY2_(PASSWORD|OBFS_PASSWORD|PORT_RANGE)=" "$SB/etc/airport-tool/hysteria2.env")
h_crt=$(md5sum < "$SB/etc/hysteria/server.crt")
out=$(sb_flag --export-state "$SB/state.tgz" 2>&1); rc=$?
if [[ $rc -eq 0 && -f "$SB/state.tgz" ]] && grep -q 'umask 077' "$SRC" \
   && tar -tzf "$SB/state.tgz" | grep -q 'etc/airport-tool/reality.env' \
   && tar -tzf "$SB/state.tgz" | grep -q 'etc/hysteria/server.key' \
   && ! tar -tzf "$SB/state.tgz" | grep -q 'hy2-hop.sh'; then
  echo "   ✓ exported state, keys and certificates (created under umask 077, chmod 600)"
else
  echo "   ✗ export failed (rc=$rc):"; echo "$out" | tail -3 | sed 's/^/     /'; fails=$((fails + 1))
fi
# "A new VPS": none of the old files, and a different public address.
mv "$SB/state.tgz" "$SB/../state.$$.tgz"
rm -rf "$SB"; make_stubs; sandbox_script
mv "$SB/../state.$$.tgz" "$SB/state.tgz"
echo "198.51.100.50" > "$SB/ip.ifconfig.me.4"
out=$(sb_flag --import-state "$SB/state.tgz" 2>&1); rc=$?
if [[ $rc -eq 0 ]] \
   && [[ "$(grep -E "^REALITY_(UUID|PUBLIC_KEY|PRIVATE_KEY|SHORT_ID)=" "$SB/etc/airport-tool/reality.env")" == "$r_env" ]] \
   && [[ "$(grep -E "^HY2_(PASSWORD|OBFS_PASSWORD|PORT_RANGE)=" "$SB/etc/airport-tool/hysteria2.env")" == "$h_env" ]] \
   && [[ "$(md5sum < "$SB/etc/hysteria/server.crt")" == "$h_crt" ]] \
   && grep -q '"server": "198.51.100.50"' "$SB/etc/airport-tool/reality.profile.json" \
   && grep -q -- '--dport 20000:30000 -j REDIRECT --to-ports 443' "$SB/etc/airport-tool/hy2-hop.sh" \
   && grep -q 'address changed' <<<"$out" && grep -q '203.0.113.9 → 198.51.100.50' <<<"$out"; then
  echo "   ✓ same keys, passwords, certificate and hop range; new address, and the IP change is called out"
else
  echo "   ✗ import did not reproduce the install (rc=$rc):"; echo "$out" | grep -E 'ERROR|WARN' | tail -6 | sed 's/^/     /'
  fails=$((fails + 1))
fi
# Importing the same thing again is harmless; over a different install it is not.
if sb_flag --import-state "$SB/state.tgz" >/dev/null 2>&1; then
  echo "   ✓ re-importing over the same install is allowed"
else
  echo "   ✗ re-importing the identical state was refused"; fails=$((fails + 1))
fi
cp "$SB/state.tgz" "$SB/../state.$$.tgz"
rm -rf "$SB"; make_stubs; sandbox_script
mv "$SB/../state.$$.tgz" "$SB/state.tgz"
sb_run PROTOCOL=reality >/dev/null 2>&1
mine=$(grep '^REALITY_SHORT_ID=' "$SB/etc/airport-tool/reality.env")
out=$(sb_flag --import-state "$SB/state.tgz" 2>&1); rc=$?
if [[ $rc -ne 0 ]] && grep -q 'already has a different install' <<<"$out" \
   && [[ "$(grep '^REALITY_SHORT_ID=' "$SB/etc/airport-tool/reality.env")" == "$mine" ]]; then
  echo "   ✓ refused over a different install, which is left untouched"
else
  echo "   ✗ imported over a different install without --force"; fails=$((fails + 1))
fi
if sb_flag --import-state "$SB/state.tgz" --force >/dev/null 2>&1 \
   && [[ "$(grep -E "^REALITY_(UUID|PUBLIC_KEY|PRIVATE_KEY|SHORT_ID)=" "$SB/etc/airport-tool/reality.env")" == "$r_env" ]]; then
  echo "   ✓ --force replaces it with the imported one"
else
  echo "   ✗ --force did not import"; fails=$((fails + 1))
fi
# It is unpacked as root: anything --export-state would not have written is refused.
mkdir -p "$SB/evil"; echo 'echo pwned' > "$SB/evil/x.sh"
tar -czf "$SB/evil.tgz" -C "$SB/evil" x.sh
out=$(sb_flag --import-state "$SB/evil.tgz" 2>&1)
if grep -q 'which --export-state never writes' <<<"$out"; then
  echo "   ✓ a tarball with an unexpected path is refused"
else
  echo "   ✗ an unexpected path was accepted"; fails=$((fails + 1))
fi
if sb_flag --import-state >/dev/null 2>&1 || sb_flag --doctor --upgrade >/dev/null 2>&1; then
  echo "   ✗ a missing file name or two actions at once was accepted"; fails=$((fails + 1))
else
  echo "   ✓ a missing file name, and two actions at once, are refused"
fi
if sb_flag --help 2>&1 | grep -q -- '--doctor' && sb_flag --help 2>&1 | grep -q -- '--import-state FILE' \
   && sb_flag --help 2>&1 | grep -q -- '--upgrade'; then
  echo "   ✓ --help documents the new flags"
else
  echo "   ✗ --help is missing a new flag"; fails=$((fails + 1))
fi

rm -rf "$SB"
echo ""
if [[ $fails -eq 0 ]]; then echo "setup.sh: all cases passed"; else echo "setup.sh: $fails case(s) failed"; fi
exit $((fails > 0))
