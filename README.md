# Airport Tool

Personal proxy setup for use in China. Four protocols it installs, three more it reads:

- **VLESS + Reality (Xray)** — TLS camouflage that borrows a real site's handshake. **The most DPI-resistant option** and the recommended default in 2026. Rides on raw TCP, gRPC or XHTTP.
- **Hysteria2 (QUIC/UDP)** — holds up best on lossy, heavily-shaped paths, and relays UDP. Good second server / failover.
- **TUIC v5 (QUIC/UDP)** — the same loss tolerance and real UDP relay as Hysteria2, without Hysteria2's distinctive congestion behaviour, which some ISPs shape on sight.
- **Shadowsocks** — shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS; simple, battle-tested, TCP only), or **Shadowsocks 2022** served by sing-box (no plugin, TCP *and* UDP) when you pick a `2022-blake3-*` cipher.
- **Trojan**, **VMess** and **VLESS + TLS** — *not* installed by `setup.sh`, but fully modelled: import them, generate every client config from them, probe them. A subscription somebody hands you is very likely to be one of the three, and Reality already does their job better on a server you own.

Already paying a provider? **Follow its subscription URL** instead of pasting its
servers once — see [Following a provider's subscription](#following-a-providers-subscription).

The server script, config generator, and web UI all understand every protocol and
let you manage **multiple server profiles** at once, with automatic failover between
them.

| | Reality | Hysteria2 | TUIC v5 | Shadowsocks | Trojan | VMess | VLESS + TLS |
|---|---|---|---|---|---|---|---|
| `setup.sh` installs it | **yes** | **yes** | **yes** | **yes** | no | no | no |
| Transport | TCP / gRPC / XHTTP | UDP (QUIC) | UDP (QUIC) | TCP (+UDP for 2022) | TCP / ws / gRPC | TCP / ws / gRPC | TCP / ws / gRPC |
| Relays UDP for you | yes | yes | yes | **no** (2022: yes) | yes | yes | yes |
| On a lossy link | good | **best** | very good | poor | poor | poor | poor |
| Blocked-port risk | low (looks like HTTPS) | some ISPs throttle UDP | some ISPs throttle UDP | medium | low (is HTTPS) | **high** | low (is HTTPS) |
| Port hopping | — | **yes** (`HY2_PORT_RANGE`) | — | — | — | — | — |
| Declared bandwidth | — | **yes** (`up`/`down`) | — | — | — | — | — |
| Needs a domain | no | no (self-signed) | no (self-signed) | only for TLS mode | **yes** (real cert) | only for TLS mode | **yes** (real cert) |

Run two of them on separate servers and the generated configs will fail over
automatically — see [Failover](#failover).

---

## Quick Start — Get Online from China

**How it works:** you rent a small server (VPS) *outside* China, run one setup script
on it, then import the generated config into a phone/PC app *inside* China. Your
traffic is encrypted and disguised as normal HTTPS, so the Great Firewall lets it
through. The server must live outside mainland China — a domestic VPS won't help.

Do steps 1–4 **before** you travel / while you still have open internet, because
downloading the client apps and this repo is hard once you're behind the firewall.

**1. Rent a VPS outside China.** Cheapest good option: an [Oracle Cloud](https://www.oracle.com/cloud/free/)
always-free ARM instance in **Tokyo**. In its firewall / security group, open
**443/tcp**. Note the server's public IP. (More options in [Step 1](#step-1--get-a-free--cheap-vps).)

**2. Set up the server (run once, on the VPS).** Copy the script over and run it:

```bash
scp server/setup.sh root@YOUR_VPS_IP:/root/
ssh root@YOUR_VPS_IP
PROTOCOL=reality bash setup.sh          # Reality = best at evading the firewall
```

When it finishes it prints your connection details and saves a ready-to-import
profile to `/etc/airport-tool/profile.json`. **Copy that whole block of text** —
you'll paste it in the next step. (Print it again anytime with
`cat /etc/airport-tool/profile.json`.)

**3. Generate your client config (on your PC).** Two ways — pick one:

*Option A — web UI (easiest):*
```bash
cd web-ui && npm install && npm start
```
Open <http://localhost:3000>, paste the profile block from step 2 into the
**Import** box, and click **Import**. A QR code and a **Subscription URL** appear.
(You can also click **+ New Profile** and type the fields in by hand.)

*Option B — command line:*
```bash
cd config-gen && npm install
node gen.js --add /path/to/profile.json     # paste-free import from step 2
```

Or set the file up by hand:
```bash
cd config-gen
cp servers.json.example servers.json
# edit servers.json — paste the profile from step 2 into the "profiles" array
npm install && node gen.js
```
Configs land in `config-gen/output/` (`clash-config.yaml`, `singbox-config.json`,
`qrcode.png`, …).

**4. Install a client app and import the config.**

| Your device | App to install | How to import |
|---|---|---|
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | Scan the QR code |
| iPhone | [Sing-Box](https://apps.apple.com/app/sing-box/id6451272673) (free) | Import `singbox-config.json` |
| Windows | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Import `clash-config.yaml`, or subscribe to the URL with `?target=clash` |
| macOS | [ClashX Meta](https://github.com/MetaCubeX/ClashX.Meta) | Import `clash-config.yaml` |
| iPhone/macOS (paid) | [Surge](https://nssurge.com/) | Import `surge.conf` |
| iPhone (paid) | [Quantumult X](https://apps.apple.com/app/quantumult-x/id1443988620) | Import `quantumultx.conf` |

> **If you use Surge or Quantumult X:** neither can express every protocol here.
> Surge has no VLESS/Reality (it does carry Hysteria2, with Salamander from Mac
> 6.4.3, and TUIC v5); Quantumult X carries Reality over raw TCP only and has no
> QUIC protocols at all. Rather than hand you a config that is quietly missing a
> server, both generated files name each omission in a comment, and the
> dashboard shows the count ("Surge: 3 of 5 servers") next to the download
> button. If your only servers are Reality over gRPC or XHTTP, use Sing-Box or
> Clash instead.

**5. Turn it on.** In the app, select your profile and tap **Connect**. Verify it
works by visiting a blocked site (e.g. google.com) or checking that your IP now
shows your VPS's country at <https://ipinfo.io>.

> **Tip:** test the connection from *outside* China first to confirm the server
> works, then rely on it from inside. If it stops connecting later, your VPS IP may
> have been blocked — spin up a second server and add it as another profile (this
> tool manages several at once). See [Troubleshooting](#troubleshooting).

---

## Project Structure

```
airport-tool/
├── server/
│   ├── setup.sh              # Run on your VPS. PROTOCOL=reality|hysteria2|tuic|shadowsocks
│   └── test-setup.sh         # Smoke-tests setup.sh against stubbed system commands
├── config-gen/
│   ├── gen.js                # CLI: generates configs + QR + subscription, and --test
│   ├── lib/configs.js        # Shared model + builders (protocols, URIs, Clash, Sing-Box)
│   ├── lib/clients.js        # Surge + Quantumult X output, and what neither can carry
│   ├── lib/probe.js          # Shared connectivity probes (tcp / tls / deep) + cert expiry
│   ├── lib/history.js        # Shared probe-history file + monitor state
│   ├── lib/alert.js          # Turns a monitor pass into an outbound notification
│   ├── test.js               # Tests for the above (npm test)
│   ├── test-cli.js           # gen.js at the process boundary: --add - and --test --alert
│   ├── test-real-clients.js  # Every bundle through a real sing-box and mihomo
│   ├── servers.json          # Your profiles + subscription token (create from .example)
│   └── servers.json.example
├── web-ui/
│   ├── server.js             # Express web server + REST API + subscription endpoint
│   ├── public/index.html     # Dashboard UI
│   ├── airport-ui.service    # systemd unit template
│   ├── install-service.sh    # Fills the unit in for this machine and starts it
│   └── test/
│       ├── api.js            # Auth, CSRF, CRUD, import, downloads, rotation, restore,
│       │                     #   enable/disable, device tokens, alerts, TLS, monitor,
│       │                     #   hardening headers, title, alert threshold
│       ├── deep-test.js      # The deep connection probe, end to end
│       └── fake-sing-box.js  # Stand-in binary the deep test drives
├── Dockerfile                # The dashboard as a container (see Running as a service)
└── docker-compose.yml
```

`config-gen/servers.json` is the single source of truth — the CLI and the web UI
share it. It holds your proxy passwords, the subscription token **and** the
dashboard token, so it is written `0600` and is in `.gitignore`. Never commit it.
Probe results live separately in `test-history.json` next to it: they are written
on every test, and churning a file full of credentials that often is a good way
to eventually lose it.

`lib/probe.js` and `lib/history.js` are shared for the same reason `lib/configs.js`
is: `gen.js --test` and the dashboard's **Test All** button must measure the same
things and file the results in the same place, or the two disagree about which of
your servers is up.

---

## Step 1 — Get a Free / Cheap VPS

| Provider | Free tier | Cheapest paid | Best region for China |
|---|---|---|---|
| **Oracle Cloud** | Always-free ARM (1 OCPU, 1 GB RAM) | — | Tokyo / Osaka / Singapore |
| **Vultr** | — | $2.50/mo (IPv6) / $6/mo | Tokyo, Singapore |
| **DigitalOcean** | — | $6/mo | Singapore, San Francisco |
| **AWS Lightsail** | 3 months free | $3.50/mo | Tokyo, Singapore |

**Recommended:** Oracle Cloud Free Tier (Tokyo) — free forever. Open the port in
the provider's security group: **443/tcp** for Reality, **443/udp** for Hysteria2
(UDP, not TCP), **8388/tcp** (or 443) for Shadowsocks.

---

## Step 2 — Set Up the Server

Copy the script to your VPS and run it as root. The simplest way (no GitHub
needed) is `scp`, from the folder that holds this repo on your PC:

```bash
scp server/setup.sh root@YOUR_VPS_IP:/root/
ssh root@YOUR_VPS_IP
```

Then, on the VPS, pick a protocol:

```bash
# VLESS + Reality (recommended — most DPI-resistant)
PROTOCOL=reality bash setup.sh

# Reality over gRPC or XHTTP instead of raw TCP. Both drop the xtls-rprx-vision
# flow, which only works over TCP; the client profile is adjusted to match.
PROTOCOL=reality REALITY_NETWORK=grpc bash setup.sh

# Hysteria2 (UDP/QUIC — best on a lossy link, and relays UDP)
PROTOCOL=hysteria2 bash setup.sh

# Hysteria2 with a real certificate instead of a self-signed one
PROTOCOL=hysteria2 DOMAIN=proxy.example.com bash setup.sh

# Hysteria2 with port hopping — the client rotates across a whole UDP range,
# which survives a block or a throttle aimed at one port. Open the range in
# your cloud firewall too.
PROTOCOL=hysteria2 HY2_PORT_RANGE=20000-30000 bash setup.sh

# Hysteria2 showing a different site to anyone who probes the port without
# credentials. Must be somewhere else on the internet, never your own domain.
PROTOCOL=hysteria2 HY2_MASQUERADE=www.apple.com bash setup.sh

# TUIC v5 (UDP/QUIC, served by sing-box)
PROTOCOL=tuic bash setup.sh

# Shadowsocks + v2ray-plugin (WebSocket)
SS_PORT=8388 SS_PASSWORD="strong-pw" bash setup.sh

# Shadowsocks with real TLS (needs a domain pointed at the server)
DOMAIN=proxy.example.com V2RAY_PLUGIN_MODE=tls bash setup.sh

# Shadowsocks 2022 — replay-protected, relays UDP, no plugin. Served by
# sing-box, because shadowsocks-libev never implemented the 2022 ciphers.
# The key is generated for you (base64 of 16 or 32 bytes, by cipher).
PROTOCOL=shadowsocks SS_METHOD=2022-blake3-aes-256-gcm bash setup.sh
```

> **Pinned installers.** Xray, Hysteria2 and sing-box come from their own
> install scripts, at the releases this repo was tested against
> (`XRAY_VERSION`, `HY2_VERSION`, `SINGBOX_VERSION` at the top of `setup.sh`).
> They used to install whatever was newest that day, so the same command set up
> different software from one week to the next. Set one to `latest` to opt back
> in, or to a specific tag to pick your own.

> **Hysteria2 masquerading.** Anything that probes the port without valid
> credentials is shown a real website instead of a protocol error — that is the
> camouflage, and it is most of what makes an unadvertised UDP port
> uninteresting. The target has to be *somewhere else*: pointing it at this
> server's own domain makes Hysteria2 fetch from a TCP port it is not listening
> on, so the prober gets an error and learns that something unusual lives here
> after all. `HY2_MASQUERADE` defaults to `www.bing.com`, and a value equal to
> your `DOMAIN` is refused rather than used.

Re-running with no environment set reuses **everything** recorded in
`/etc/airport-tool/<protocol>.env` — keys, passwords, ports and SNI alike — so
clients you have already handed out keep working. Name a variable explicitly to
change just that one, or pass `FORCE=1` to mint new secrets. To look at what is
installed without touching it, use `bash setup.sh --show`.

**Several protocols on one server.** Each protocol keeps its own state file, so
installing a second one leaves the first entirely alone:

```bash
PROTOCOL=reality   bash setup.sh      # TCP/443
PROTOCOL=hysteria2 HY2_PORT=8443 bash setup.sh   # UDP/8443, Reality untouched
bash setup.sh --show                  # prints both, with certificate expiry
```

Give them different ports — two servers cannot bind the same one, though a TCP
and a UDP protocol can share a number (Reality on 443/tcp beside Hysteria2 on
443/udp is fine). `setup.sh` checks this before installing anything: a second
protocol on a port another already holds — Hysteria2 and TUIC both default to
443/udp — is refused with the variable that fixes it, and so is a Hysteria2 hop
range that would swallow another protocol's UDP port. Uninstalling one only
closes the transport it opened, so removing Hysteria2 leaves Reality's
443/tcp alone. `--show` reports how long each certificate has left, which is
the failure that otherwise happens quietly while you are not looking.

Values you pass in are checked before anything is installed — ports, hostnames,
UUIDs, `V2RAY_PLUGIN_MODE=tls` without a `DOMAIN`, and Shadowsocks 2022 ciphers,
which shadowsocks-libev does not implement — and passwords are quoted properly
into every JSON and YAML file, so one containing a quote, a backslash, a colon or
a `#` arrives intact. The v2ray-plugin download is verified against the
checksum of the published release before it is installed.

Add `--json` and it prints the client profiles instead — a JSON array on stdout
and nothing else, with every diagnostic on stderr — so the whole server can be
imported in one command from your PC:

```bash
ssh root@YOUR_VPS_IP 'bash /root/setup.sh --show --json' | node gen.js --add -
```

> If you host this repo on GitHub yourself, you can instead pipe it in one line —
> replace `YOUR_GH_USER` with your username:
> `PROTOCOL=reality bash <(curl -sL https://raw.githubusercontent.com/YOUR_GH_USER/airport-tool/main/server/setup.sh)`

The script installs everything, enables the systemd service, opens the firewall,
turns on BBR, verifies the service actually started, prints the connection
details, and writes a ready-to-import profile to
**`/etc/airport-tool/profile.json`**. Feed that file straight into the tools on
your PC with `node gen.js --add …` or the web UI's Import box.

**Env knobs**

| Variable | Applies to | Default | Meaning |
|---|---|---|---|
| `PROTOCOL` | all | `shadowsocks` | `reality` \| `hysteria2` \| `shadowsocks` |
| `FORCE` | all | `0` | `1` = regenerate keys even if a setup exists |
| `NO_BBR` | all | `0` | `1` = skip the BBR / socket-buffer tuning |
| `DOMAIN` | hysteria2, SS-TLS | — | real certificate via ACME / certbot |
| `REALITY_PORT` / `REALITY_SNI` | reality | `443` / `www.microsoft.com` | port, borrowed TLS domain |
| `HY2_PORT` / `HY2_SNI` | hysteria2 | `443` / `www.bing.com` | UDP port, self-signed cert name |
| `HY2_PASSWORD` / `HY2_OBFS` | hysteria2 | random / `1` | password, salamander obfuscation |
| `HY2_PORT_RANGE` | hysteria2 | — | e.g. `20000-30000`; UDP range to hop across |
| `HY2_UP` | hysteria2 | — | Client upload rate in Mbps. Needed for Brutal |
| `HY2_DOWN` | hysteria2 | — | Client download rate in Mbps. Needed for Brutal |
| `TUIC_PORT` / `TUIC_SNI` | tuic | `443` / `www.bing.com` | UDP port, self-signed cert name |
| `TUIC_UUID` / `TUIC_PASSWORD` | tuic | random | credentials |
| `SS_PORT` / `SS_PASSWORD` / `SS_METHOD` | shadowsocks | `8388` / random / chacha20 | |
| `V2RAY_PLUGIN_MODE` | shadowsocks | `websocket` | `tls` needs `DOMAIN` |

For Reality, the script auto-generates the x25519 keypair, UUID and short ID via
`xray`, camouflages behind `REALITY_SNI`, and warns you if that site doesn't
actually complete a TLS 1.3 handshake (which would make the camouflage useless).

**Re-running is safe.** A second run reuses the existing keys, UUID and passwords,
so clients you've already set up keep working. Pass `FORCE=1` when you deliberately
want new credentials — that invalidates every existing client.

**Removing it:**
```bash
bash setup.sh --uninstall                      # only if exactly one is installed
PROTOCOL=hysteria2 bash setup.sh --uninstall   # name it when several are
bash setup.sh --help
```

Uninstalling one protocol leaves the others running: it removes only that
protocol's service, config, state file and firewall rules. The shared kernel
tuning and `/etc/airport-tool` go only when the last one does. With more than
one installed, a bare `--uninstall` refuses rather than guessing.

**Port hopping (Hysteria2).** `HY2_PORT_RANGE=20000-30000` adds an iptables NAT
rule redirecting that whole UDP range to the real listening port, and puts
`mport=20000-30000` in the generated client URI so clients rotate across it.
That defeats a block or a throttle aimed at a single port — the failure mode the
protocol table above calls out for UDP. Two caveats: **open the entire range for
UDP in your provider's security group**, or clients stall on ports that never
answer; and if the range fails to apply, the script drops it rather than
advertising a range nothing is listening on.

**Firewalls.** The script uses whichever firewall is actually active — `ufw`,
`firewalld`, or raw `iptables` — and persists the rule. The iptables fallback
matters: Oracle Cloud and AWS images ship an `INPUT` chain that rejects everything
except port 22 and have no `ufw`, which is the most common reason a server
"installs fine" but never accepts a connection. You still have to open the port in
your **provider's** security group yourself; nothing on the box can do that for you.
Hysteria2 needs the port opened for **UDP**.

---

## Step 3 — Generate Client Configs (on your PC)

```bash
cd config-gen
npm install

# Easiest: import the server's own profile.json, or any share link
node gen.js --add /path/to/profile.json
node gen.js --add "vless://…"
node gen.js --add "hysteria2://…"
node gen.js --add "tuic://…"

# Or pull every protocol off the server in one command, without copying a file
# (the path is wherever step 2 put setup.sh — /root/ if you followed it exactly):
ssh root@YOUR_VPS_IP 'bash /root/setup.sh --show --json' | node gen.js --add -

# Or set it up by hand
cp servers.json.example servers.json
# Edit servers.json: paste the profile(s) from /etc/airport-tool/profile.json
node gen.js

# Point at another file: node gen.js --config /path/to/other.json
# Back the whole store up somewhere safe and stop:
node gen.js --export ~/backups/servers.json

# Follow a provider's subscription URL: fetch it, merge its servers in, generate.
node gen.js --add-source "https://provider.example/sub?token=…" --name "Provider"
# Re-fetch every source (cron-friendly: non-zero exit if one failed), then generate:
node gen.js --refresh

# Probe every server and stop, without regenerating anything:
node gen.js --test
node gen.js --test --deep      # dial through each one with a local sing-box
node gen.js --test --json      # machine-readable, for cron or a monitoring agent
node gen.js --test --alert     # …and notify the configured webhook if it changed
```

`--test` runs exactly the probes the dashboard's **Test All Servers** button
runs, and files the results in the same `test-history.json`, so the CLI and the
UI agree about which servers are up:

```
✓ Tokyo - Reality ★ (vless-reality)
    38ms · TLS handshake OK (TLSv1.3) with SNI www.microsoft.com  [avg 41ms, 100% up, over 12]
— Osaka - TUIC (tuic)
    tuic runs over UDP/QUIC — reachability can't be probed from here. Use the deep test.

1/2 reachable (1 untestable without --deep). History: …/test-history.json
```

It exits non-zero when nothing answered, so it drops straight into a cron job or
a monitoring check. It exits **zero** when nothing could be *asked* — a store
holding only Hysteria2 and TUIC profiles, probed without `--deep`, produces no
successes at all because QUIC over UDP cannot be reached from outside the
protocol. Those two states are different, and treating them alike made a
QUIC-only store fail on every single run: an alarm that is always on is one
nobody reads.

`--deep` is the only mode that says anything about a QUIC profile, and the only
one that proves the credentials work — so on a QUIC-only store it is also the
only mode whose exit code means anything.

Add `--json` when something other than a person is reading. The decorated output
above is for humans and will keep changing; this is the contract:

```json
{
  "at": "2026-08-23T10:18:55.988Z",
  "state": "degraded",
  "up": 1, "down": 1, "untestable": 1, "total": 3,
  "servers": [
    { "remarks": "Tokyo - Reality", "ok": true, "latencyMs": 38, "enabled": true,
      "active": true, "cert": { "daysLeft": 61, "expiring": false, "of": "camouflage target" },
      "avgMs": 41, "successRate": 100 }
  ]
}
```

Where a TLS handshake is possible, the probe also **dates the certificate** —
`cert.daysLeft`, and a warning line in the human output once it is inside 14
days or already gone. An expired certificate is the failure that arrives on its
own while you do nothing, and from the client side it looks like the server
simply stopped working. Hysteria2 and TUIC serve theirs inside QUIC, which
nothing here speaks, so for those the probe says so rather than leaving a blank:
run `setup.sh --show` on the server to date those.

`--add` accepts a share link, several links on separate lines, a base64
subscription blob (standard or URL-safe alphabet), a JSON profile, or a JSON
array of them. Duplicates (same protocol + server + port) are skipped rather
than added twice. `--add -` reads from stdin, which is what makes the
`setup.sh --show --json | node gen.js --add -` pipe above work — the
credentials go straight from the server into the store without landing in a
file on the way.

`--alert` POSTs the result of a `--test` run to the webhook configured under
`monitor.alert` (set it in the dashboard, under **Background Health Monitor**).
It is the cron half of the dashboard's health monitor, for when you would rather
not leave the dashboard running:

```cron
*/15 * * * * cd ~/airport-tool/config-gen && /usr/local/bin/node gen.js --test --alert >/dev/null
```

Spell `node` out in full: cron runs with a minimal `PATH`, and a job that dies
with "node: command not found" is a monitor that silently never reports. `which
node` gives you the path to use.

Like the monitor it speaks on a *transition* — the first run that finds
everything down, and the first that finds something back — rather than every
fifteen minutes, because an alert that repeats is one you learn to swipe away.
The state it compares against lives in `monitor-state.json` beside the store,
so the cron job and the dashboard agree about what the current state is instead
of each re-alerting over the other.

Output in `config-gen/output/` (directory `0700`, files `0600` — every one of
them carries proxy passwords in plain text, and the QR encodes one):
- `clash-config.yaml` — Clash.Meta / Mihomo (every **enabled** profile)
- `singbox-config.json` — Sing-Box (every enabled profile, with a selector)
- `surge.conf` — Surge, for the protocols it supports; the rest are named in
  comments rather than silently dropped
- `quantumultx.conf` — Quantumult X, on the same terms
- `subscription-base64.txt` — subscription blob (every enabled profile)
- `uris.txt` — every enabled profile's import URI
- `active-uri.txt` + `qrcode.png` — the active profile, ready to scan
- `summary.json` — every profile including the disabled ones, each flagged

`servers.json` holds **multiple profiles**; `active` is the index of the one used
for the QR code. A single legacy `server.json` object still works. Two more
files sit beside it, both `0600` and neither holding credentials:
`test-history.json` (probe samples) and `monitor-state.json` (which alert state
was last sent, and when each device token last polled). They are separate
because both are written often, and churning the file that holds every password
you own is a good way to eventually lose it. All three are in `.gitignore`,
along with the `ui-cert.pem` / `ui-key.pem` pair `TLS_SELFSIGNED=1` mints.

**Disabling instead of deleting.** Set `"enabled": false` on a profile (or press
*Disable Selected* in the dashboard) and it stays in the store while leaving
every generated file, the subscription feed and the failover group. That matters
because deleting is not the reversible act it looks like: `setup.sh` cannot
reproduce a password it already minted, so a deleted profile is a server you
have to rebuild. A blocked VPS you might come back to belongs in the store,
disabled — the probes still cover it, so you find out when it starts answering
again. ★ never sits on a disabled profile, and generation refuses to run if you
turn them all off rather than emitting a config with no servers in it.

---

## Step 4 — Web UI (optional, run locally)

```bash
cd web-ui
npm install
npm start
# Open http://localhost:3000
```

Features:
- Manage **multiple server profiles** (add / edit / delete, switch active with a double-click)
- **Reorder them** with *◀ Move* / *Move ▶*. The order is not decoration: it is
  the order `uris.txt` comes out in, the order both selectors list their proxies
  in, and — in the Clash bundle's `Fallback` group — the order a client walks
  when the one above it does not answer. ★ follows the profile it was on rather
  than the slot. (Sing-Box has no group type that respects order; see
  [Failover](#failover).)
- **Enable / disable a profile** without deleting it — a blocked server leaves
  every generated config and the subscription feed but keeps its credentials,
  which `setup.sh` cannot mint again. It is still probed, so you learn when it
  comes back
- **Seven protocols**: Reality (TCP/gRPC/XHTTP), Hysteria2, TUIC v5, Shadowsocks,
  Trojan, VMess and VLESS + TLS, with protocol-aware fields
- **Subscription Sources**: follow a provider's subscription URL, refreshed on
  a schedule — see [Following a provider's subscription](#following-a-providers-subscription)
- A **latency sparkline** per profile, drawn from the last twenty probes. One
  probe is weather; the shape of twenty is what tells you a server has been
  getting steadily worse rather than having had one bad morning
- **Import** — paste a share link, several links, a subscription blob (standard
  base64 or base64url), or the server's `profile.json`, instead of retyping six fields
- **Generate** buttons for strong passwords and UUIDs
- Live QR code (scan with phone), and a **QR of the subscription URL** so you
  never type a 32-character token into a phone by hand
- **Subscription URL** for auto-updating clients — token-gated (see below), with
  **Rotate Subscription Token** / **Rotate Dashboard Token** buttons. Rotating
  revokes the old URL immediately, which is the fix for a subscription link that
  ended up somewhere it shouldn't have. (The dashboard token cannot be rotated
  from here when `UI_TOKEN` pins it — change the variable and restart instead.)
- **Subscribe to the whole config, not just the servers.** The plain
  subscription URL is a base64 URI list, which is what a scanned QR code has to
  be — but a URI list is *only servers*. Everything this project knows about
  getting out of China lives in the generated Clash and Sing-Box configs: the
  domestic-first DNS split, the DoH fallback that rides the tunnel, the fake-ip
  exemptions, the CN-direct rules, the geo mirrors that are reachable from
  behind the firewall. A client that subscribes to the URI list sees none of it
  — Clash Verge converts the list using its own defaults instead — so the person
  who did the easy thing got a working proxy with the routing quietly replaced.

  Add `?target=` to the same URL and the feed renders the whole config:

  ```
  …/api/subscription/<token>?target=clash
  …/api/subscription/<token>?target=singbox
  …/api/subscription/<token>?target=singbox-desktop   # no tun; no root needed
  …/api/subscription/<token>?target=surge
  …/api/subscription/<token>?target=quantumultx
  ```

  Same token, same gate, same per-device URLs — and unlike the downloaded file,
  it keeps updating. The dashboard lists all five ready to copy. Leave `target`
  off and you get the URI list exactly as before.
- **A name for the subscription.** *Shown in clients as …* sets the
  `profile-title` header; without it a client lists this subscription by its raw
  URL — token included — in its profile list, and therefore in every screenshot
  of that list. The feed also sends `profile-web-page-url` pointing back at the
  dashboard, which is where "open the provider's page" goes in Clash Verge
- **Per-device subscription URLs.** Issue a named token per phone and laptop.
  A device you lose — or a friend you stop sharing with — can be cut off on its
  own, instead of rotating the shared token and re-pointing everything you own.
  Each has its own QR, and the dashboard shows when it last polled — persisted,
  so "never polled" means the device really has never arrived rather than that
  the dashboard restarted.

  Each URL can also be **limited to some of your servers** (*Servers…* on the
  device, or pick them when issuing it): hand a friend one box without handing
  over the rest. "All servers" includes ones you add later; a limited URL only
  ever gets the servers you ticked, in every `?target=` too. Changing the list
  keeps the URL. If every server a device may use is deleted or disabled, its
  feed answers `409` with the reason rather than silently widening to
  everything. Over the API: `POST /api/clients` and `POST /api/clients/<id>`
  take `"profiles": [ids]`, or `null` for all.
- **Routing Rules** — your own *always direct*, *always through the tunnel* and
  *block* lists, one domain (subdomains included) or CIDR range per line. They
  go ahead of every geographic rule in every bundle and subscription target —
  Clash, Sing-Box, Surge and Quantumult X each in its own spelling — so a bank
  that refuses foreign IPs, a work VPN or a `.cn` site hosted abroad can be
  routed the way you need without hand-editing a generated file that the next
  generate run would overwrite. A typo is refused with the reason, and so is an
  entry in two lists. They live in `servers.json` under `"rules"`, so `gen.js`
  applies them too.
- Download Clash.Meta, Sing-Box, **Surge**, **Quantumult X** and URI configs —
  plus **Backup `servers.json`** and **Restore from Backup**, which puts back the
  profiles *and* both tokens, so subscription URLs you already handed out start
  working again. For Surge and Quantumult X the dashboard says how many of your
  servers each can actually carry, and why the others were left out, *before* you
  download
- Two Sing-Box downloads: the **mobile** config carries a `tun` interface (the
  phone apps supply it), and the **desktop CLI** config leaves it out — `tun`
  needs root/Administrator, so the mobile config simply dies on a laptop. The
  desktop build listens on `127.0.0.1:2080` instead.
- **Test Connection**, at two depths:
  - *shallow* (default) — TCP reachability, plus a real **TLS handshake** with the
    configured SNI for Reality / TLS profiles. No dependencies, but it cannot say
    anything about a QUIC profile, where a silent UDP port and a dropped one look
    identical.
  - *deep* — dials **through the proxy** using a local `sing-box` and fetches a
    204. This is the only check that proves your credentials work and that traffic
    actually comes back, and the only one that means anything for Hysteria2 and
    TUIC. Install `sing-box` on the machine running the UI to enable it (or point
    `SINGBOX_BIN` at it; `SINGBOX_ARGS` prefixes arguments if you reach it through
    a wrapper). The Docker image ships with it.
- **Test All Servers** — probes every profile at once and ranks them by latency
- **Use Fastest ★** — probes everything, then moves the active profile to the
  fastest server that answered
- **Probe history** — the last 30 results per profile, kept in `test-history.json`
  next to the store, shown as an average and an uptime percentage. One probe is
  weather; twenty are climate. A profile's history is deleted along with it.
- **Background Health Monitor** — probes every server on a timer and files the
  results in that same history, so "which server should I be on right now?"
  already has an answer when you come to ask it. Off by default; the interval,
  shallow-vs-deep, and whether it may move the ★ to the fastest server that
  answered are all separate switches. The settings live in `servers.json`, so
  they survive a restart. Turning on *move ★* is a bigger promise than measuring
  — a flaky probe should not silently repoint your clients — which is why it is
  opt-in on its own.
- **Notifications when something breaks.** The monitor already knows when every
  server has stopped answering; without this the only way to find out is to open
  this page, which is the one thing you cannot do from behind the firewall when
  nothing is reachable. Point it at a webhook and it tells you — see
  [Getting told when a server goes down](#getting-told-when-a-server-goes-down).
- **Certificate expiry**, wherever a TLS handshake can observe one. Inside 14
  days it turns amber, past the date it turns red. This is the failure that
  arrives on its own while you do nothing.

### Getting told when a server goes down

Tick **Send a notification to a webhook** under the health monitor, paste a URL,
and press *Send a test notification* to confirm it arrives. Set this up **before
you travel**: configuring it from the side of the firewall where you cannot
reach the dashboard is exactly the situation it exists for.

| Service | URL | Format |
|---|---|---|
| [ntfy.sh](https://ntfy.sh) | `https://ntfy.sh/some-long-private-topic` | Plain text |
| Slack | an Incoming Webhook URL | JSON |
| Discord | a channel webhook URL | JSON |
| Anything of your own | any `http(s)` endpoint | JSON |

The JSON body carries the same sentence three times — as `text`, `content` *and*
`message` — so one payload satisfies Slack, Discord and a generic receiver
without picking a vendor. It also carries `state`, `up`/`down`/`total` and a
per-server breakdown for anything that wants to parse it.

Notifications fire on **changes**: everything goes down, something comes back,
or ★ moves to a different server. There is a switch for one per pass, but the
default is deliberate — an hourly "still down" is how people learn to swipe the
notification away without reading it. Two things never trigger one on their own:
a *disabled* profile being unreachable (that is the expected state, not an
incident), and a pass where every profile was untestable — bare QUIC without the
deep test answers neither way, and reporting "we could not ask" as "everything
is down" would make the alert lie in exactly the case the deep test exists for.
The same goes for a deep probe of Reality over XHTTP: sing-box has no XHTTP
transport, so that server is reported as untestable rather than as down.

A notification the webhook did not accept is **retried on the next pass**. The
change is only recorded as told once a message actually landed, so a receiver
that was itself down when everything broke does not swallow the alert for good.

**Only after N consecutive failed passes** (`monitor.alert.afterFailures`, 1–10)
debounces a flapping server. The paths this tool exists for are lossy by nature,
so a single failed probe is often just the link being the link — and an alert
that fires at 3am for a server that was fine again by 3:01 is one you learn to
mute, which costs more than the outage it was reporting. At `3` a server has to
be unreachable three passes running before anything is sent.

The held-back transition is *not* forgotten while it waits, which is the part
that is easy to get wrong: if a suppressed "down" were recorded as the current
state, the transition would be consumed by the pass that deliberately stayed
quiet and the real alert would never fire at all. A failure that clears before
reaching the threshold therefore says nothing in either direction — there was
never an outage to announce, so there is nothing to retract. While a transition
is being held the dashboard says so ("down for 1 of the 3 passes it takes"), so a
suppressed failure never looks the same as no failure. The streak lives in
`monitor-state.json` beside the last state, so a restart does not hand every
deploy a fresh grace period.

A pass that could *not* ask — every profile untestable — does not reset the
streak either. Two real failures either side of one unmeasurable pass is still a
server that is down.

A webhook that cannot be reached is reported in the dashboard rather than
swallowed. Silence otherwise reads as good news, which is the worst possible
failure mode for an alerting system.

> **The monitor only runs while the dashboard process does.** Started from a
> terminal, it dies with the terminal. See [Running it as a
> service](#running-it-as-a-service) — or skip the dashboard entirely and run
> `node gen.js --test --alert` from cron, which sends the same notification to
> the same webhook using the same transition state. The two share
> `monitor-state.json`, so running both does not double up the alerts.

---

### Running it as a service

The background monitor — and therefore the notification above — exists only
while `server.js` is running. A monitor that stops when you close your laptop
cannot tell you a server went down.

```bash
cd web-ui && npm install
sudo bash install-service.sh          # install, enable and start
sudo bash install-service.sh --uninstall
```

It fills in `airport-ui.service` for this machine: the path to `node`, this
checkout, and the user that owns it — never root, since the process needs
nothing beyond the file holding your credentials. Then:

```bash
journalctl -u airport-ui -f           # the log, including the dashboard URL
systemctl restart airport-ui
```

The unit has commented-out `UI_TOKEN`, `TLS_SELFSIGNED` and `SINGBOX_BIN` lines;
uncomment them there rather than exporting variables somewhere systemd cannot
see.

#### …or as a container

On anything that is not a systemd box — a NAS, a laptop, a Windows machine —
there is a `Dockerfile` and a `docker-compose.yml` at the repo root:

```bash
docker compose up -d
docker compose logs dashboard     # the dashboard URL, token included, is here
```

Everything stateful lives in one volume at `/data`: `servers.json` and, beside
it, the probe history, the monitor state and (with `TLS_SELFSIGNED=1`) the
dashboard certificate. **That volume is the thing to back up** — losing
`servers.json` means re-running `setup.sh` on every server, and `setup.sh` cannot
reproduce a password it already minted.

The compose file publishes to `127.0.0.1:3000` by default and ships `UI_TOKEN`
and `TLS_SELFSIGNED` commented out with a note about when they stop being
optional (the moment you change that binding). The container runs as the
unprivileged `node` user and needs no capability beyond writing that one
directory. The image carries `sing-box` (copied from the upstream image, pinned
by the `SINGBOX_VERSION` build argument), so the deep connection test and a
deep health monitor work out of the box.

Behind a reverse proxy, set `PUBLIC_URL=https://airport.example.com`: requests
then arrive from the proxy over plain HTTP, and without it every subscription
link and QR code the dashboard hands out would point at the internal address.

#### Every environment variable both tools read

| Variable | Read by | Default | What it does |
|---|---|---|---|
| `HOST`, `PORT` | dashboard | `127.0.0.1`, `3000` | Where to listen. Off loopback the token becomes mandatory. |
| `UI_TOKEN` | dashboard | minted into the store | Pins the dashboard token so it survives the store being reset. Must be at least 16 characters — the dashboard refuses to start with less, because this is the only thing standing between whoever can reach the port and every credential in the file. |
| `ALLOWED_HOSTS` | dashboard | — | Extra hostnames the `Host` allow-list accepts, comma-separated. |
| `PUBLIC_URL` | dashboard | — | The origin clients should use when a reverse proxy sits in front, e.g. `https://airport.example.com`. Every subscription link, QR code and `profile-web-page-url` is built from it; its host is allowed automatically, and an `https` one makes the dashboard cookie `Secure`. Origin only — a path is refused at start-up, because the page cannot run under one. |
| `TLS_CERT` / `TLS_KEY` | dashboard | — | Serve HTTPS with a certificate you already have. Both or neither. |
| `TLS_SELFSIGNED` | dashboard | off | Mint one next to the store instead. |
| `CFG_PATH` | dashboard | `config-gen/servers.json` | Where the profile store lives. |
| `HISTORY_PATH` | both | beside the store | Where probe samples are filed. |
| `MONITOR_STATE_PATH` | both | beside the store | Where the alert state and per-device last-seen records live. |
| `SINGBOX_BIN` | both | `sing-box` | The binary the deep test drives. |
| `SINGBOX_ARGS` | both | — | Arguments to put in front of its own, for a wrapper or a container. |
| `DEEP_TEST_URL` | both | `http://www.gstatic.com/generate_204` | What the deep test fetches through the proxy. `http` and `https` both work — an https target is tunnelled with `CONNECT`. |

---

### Security of the local UI

The dashboard is an admin panel for a file full of proxy credentials, so it takes
several precautions:

- It binds to `127.0.0.1` by default. `HOST=0.0.0.0` exposes it on your LAN.
- It rejects requests whose `Host` header is a **hostname** it doesn't expect,
  which is what stops a web page you visit from reaching it via DNS rebinding.
  `localhost` and bare IP addresses are allowed; if you reach the UI through a
  DDNS name, permit it with `ALLOWED_HOSTS=my.name.example`.
- **Writes from another site are refused.** The `Host` allow-list stops a page
  *reading* this API, and the dashboard cookie is `SameSite=Strict` so it cannot
  authorise a cross-site write. Neither helps on the loopback default, where
  there is no cookie to gate: any page you happen to have open could post here
  as a CORS "simple request" — `Content-Type: text/plain` skips the preflight,
  `express.json()` then declines to parse the body, and every handler falls back
  to its defaults. `POST /api/rotate-token` with no body took its default and
  silently rotated the subscription token, breaking the URL every one of your
  clients polls. The attacker could not read the reply, but the damage does not
  need a reply. Every non-`GET` route now checks `Sec-Fetch-Site` (and `Origin`
  for older browsers); non-browsers send neither, so `curl`, the phone apps and
  the test suite are unaffected. Only the dashboard's own origin counts:
  `same-site` is refused too, because behind `PUBLIC_URL` every other page on
  the same registrable domain is "same-site" and still receives a
  `SameSite=Strict` cookie, and on loopback so is every other localhost port.
  `GET`s under `/api` are checked the same way — `/api/test-all?deep=1` starts
  a proxy per server, and a cross-site `<img>` could otherwise trigger it — with
  the subscription feed the one exception, since its URL is meant to be opened
  from anywhere.
- **HSTS under TLS.** With `TLS_*` or an `https://` `PUBLIC_URL`, responses
  carry `Strict-Transport-Security`, so a browser that has reached the dashboard
  over TLS never falls back to plain HTTP.
- **`HTTPS` for anything off loopback.** Plain HTTP never leaves the machine
  when bound to `127.0.0.1`. Once it does — a phone fetching the subscription
  URL, a tablet opening the dashboard — the token, every proxy password and the
  whole subscription feed cross the LAN in clear text, readable by anything else
  on the same Wi-Fi. `TLS_CERT=/path/cert.pem TLS_KEY=/path/key.pem` uses a
  certificate you have; `TLS_SELFSIGNED=1` mints one next to the store with
  `openssl`, covering `localhost` and this machine's LAN addresses. Browsers
  warn about it once. An unverified tunnel still beats no tunnel for a password
  on a shared network. The dashboard cookie is marked `Secure` only under TLS —
  setting that flag on a plain-HTTP origin makes the browser discard the cookie
  and lock you out of your own dashboard.
- API responses are `Cache-Control: no-store`. `GET /api/config` returns every
  proxy password and both tokens, and without the header a JSON response is
  eligible for heuristic caching.
- **A strict `Content-Security-Policy`, plus `nosniff`, `no-referrer` and
  `frame-ancestors 'none'`.** The dashboard is one self-contained page — every
  script and style inline, the only images the `data:` URIs the QR endpoints
  return, the only network calls same-origin fetches — so `default-src 'none'`
  plus those three exceptions is cheap and leaves an injected `<img>`, `<iframe>`
  or cross-origin `fetch` nowhere to go. `no-referrer` matters specifically
  because the startup URL carries `?ui_token=` until the redirect swaps it for a
  cookie, and a `Referer` is the one way that could still escape.
- **`UI_TOKEN` must be at least 16 characters.** A stored token is 24 random
  bytes and anything shorter is refused as "not a token", but the environment pin
  used to skip that check entirely — so `UI_TOKEN=x` was accepted as the sole
  guard on a LAN-exposed dashboard, and the service template ships `change-me` as
  the line to copy. It now refuses to start and tells you how to generate one.
- **Off loopback, every route requires a dashboard token.** `GET /api/config`
  returns each profile's password *and* the subscription token, and `POST
  /api/profiles` can repoint a profile at somebody else's server — so a
  `HOST=0.0.0.0` bind with only the subscription feed guarded was no protection
  at all. The token is printed as part of the startup URL:

  ```
  Airport Web UI running at http://localhost:3000/?ui_token=…
  ```

  Open that once and it is stored in an `HttpOnly; SameSite=Strict` cookie; the
  token is then stripped from the URL by a redirect, so it stops travelling
  through `Referer` headers, browser history and screenshots. Scripts can pass it
  as `?ui_token=`, an `X-UI-Token` header, or `Authorization: Bearer`. Set
  `UI_TOKEN=…` to pin your own value — which also switches authentication on for
  a loopback bind, if you share the machine.
- The **webhook is not a general-purpose fetcher.** Only `http(s)` URLs are
  accepted, and the cloud metadata endpoints (`169.254.169.254` and friends) are
  refused: they hand instance role credentials to anything that asks, and no
  notification has ever legitimately gone to one. Loopback and LAN addresses stay
  allowed, because a self-hosted ntfy is the honest case and refusing it would
  only inconvenience someone who already holds the dashboard token.
- The **subscription URL carries its own, separate token**
  (`/api/subscription/<token>`), because a client polling that feed can hold
  neither a cookie nor a header. Keeping the two apart means handing a phone the
  subscription URL does not also hand it write access to every profile. Treat it
  as a password. Both tokens live in `servers.json`; delete `token` or `uiToken`
  and restart to roll either one.
- **Per-device subscription tokens** narrow that further. The store-wide token is
  every credential you own behind one URL, and handing the same one to a phone, a
  laptop and a friend means a leak from any of them can only be fixed by
  re-pointing all three. Issue one per device instead and revoke that one. They
  live in `servers.json` alongside the shared token, and are included in a
  backup. When a device last polled is recorded in `monitor-state.json`, not in
  the store: a client hits that feed every few hours, and writing to the file
  that holds every credential that often is the churn the probe history was split
  out to avoid. It does survive a restart, so "never polled" means the device
  really has never arrived.
- The store is written through a temporary file and renamed into place, so a
  crash, a full disk or a Ctrl-C mid-write cannot leave a truncated file where
  your credentials used to be.

If `servers.json` is ever unparseable, the UI refuses to read **or** write it and
shows the error, rather than starting from an empty store and overwriting your
credentials on the next save.

**Back it up.** `setup.sh` cannot reproduce a password it generated once, so if
`servers.json` is lost, so are those servers — you would have to re-run setup on
every VPS and redistribute everything. Use the dashboard's *Backup servers.json*
button, or `node gen.js --export ~/somewhere-safe/servers.json`.

> **Note on Shadowsocks `plugin_opts`:** keep the `server` keyword in your
> profile (it describes the *server*). Client configs strip `server` and any
> `cert=`/`key=` automatically — a client must not run the plugin in server mode.
> Leave the WebSocket path empty to use the default (`/`).
>
> **Plain Shadowsocks, with no plugin.** Set `"plugin": ""` (or pick *None* in
> the dashboard) for a server that runs no plugin at all — an `ss://` link
> imported from elsewhere with no `plugin=` parameter now stays that way. The
> generated configs then carry no plugin keys, because a client that starts a
> plugin the server is not expecting simply never connects. An **absent**
> `plugin` key still means `v2ray-plugin`, which is what `setup.sh` installs, so
> every profile written before this keeps working.
>
> **`tls` is a token, not a substring.** `plugin_opts` is a `;`-delimited list,
> and it used to be searched with a plain substring test — so a perfectly
> ordinary `host=nottls.com` (or `tls.example.com`, or `hostels.io`) switched TLS
> on in the generated config. The client then wrapped its traffic in TLS the
> server was not serving, and the only symptom was a connection that never came
> up. Both the generator and the dashboard now compare whole tokens.

### Shadowsocks ciphers

`chacha20-ietf-poly1305` is the default and a fine answer. The AEAD family
(`aes-128/192/256-gcm`, `chacha20-ietf-poly1305`, `xchacha20-ietf-poly1305`) and
the **Shadowsocks 2022** ciphers are all accepted:

| Cipher | Password field |
|---|---|
| `2022-blake3-aes-128-gcm` | base64 of exactly **16 bytes** |
| `2022-blake3-aes-256-gcm` | base64 of exactly **32 bytes** |
| `2022-blake3-chacha20-poly1305` | base64 of exactly **32 bytes** |

The 2022 ciphers take a **key**, not a passphrase, and a key of the wrong length
is a hard error rather than a warning — every client rejects it, and the message
they print never names the field that is wrong. Generate one with
`openssl rand -base64 32`, or press *Generate* in the dashboard, which now knows
which cipher is selected and sizes the key to match.

A cipher this tool does not recognise is a warning rather than a refusal, so an
odd link still imports; the pre-AEAD stream ciphers (`aes-256-cfb` and friends)
import too and say what they are — no integrity check, and dropped by current
clients.

---

## Failover

With two or more profiles, the generated configs include automatic groups,
checked every few minutes against `generate_204`. Select one once and a server
that gets blocked drops out on its own. Single-profile configs skip them, since
there's nothing to fail over to.

| Group | Where | Picks |
|---|---|---|
| `Auto` (`url-test`) | Clash, Sing-Box (`auto`), Surge, Quantumult X (`Fastest`) | Whichever server is **fastest** right now |
| `Fallback` (`fallback`) | Clash, Surge, Quantumult X (`available`) | The **first server in your order** that is alive |

Both exist because they answer different questions. `url-test` ignores your
ordering entirely, which is right when the servers are interchangeable and wrong
when they are not — cheapest first, or the box whose bandwidth you have already
paid for, even when a pricier one happens to ping 20ms quicker. `Fallback` is the
group that makes the dashboard's *◀ Move* / *Move ▶* buttons mean something.

> **Sing-Box is the exception.** It ships no group type that respects order —
> `urltest` is its only automatic selector and it picks purely by latency. So in
> the Sing-Box bundle your ordering decides the order the selector *lists*
> outbounds (what you scroll through when choosing by hand) and nothing more.
> The Clash bundle is the one that can honour it.

The best pairing is **two different protocols on two different providers**: a
Reality box and a Hysteria2 (or TUIC) box fail for different reasons, so one
blocking event rarely takes out both.

### ★ leads the failover group

★ (the active profile) is the server the bundles *prefer*. In the Clash, Surge
and Quantumult X outputs — downloads and subscription feeds alike — the
`Fallback` group tries ★ first and then your order, and the selector defaults to
`Fallback`. So a subscribed client uses the server you picked while it answers,
and the next one when it does not. Moving ★ (double-click a tab, **Use Fastest
★**, or the health monitor's *move ★*) therefore reaches every client on its
next subscription update. Names never change when ★ moves, so a client that
remembers a manual choice keeps it. In Sing-Box, which has no fallback group,
★ is listed first and `auto` stays the default — trading failover for a
preference would leave a client on a dead server.

The web UI has a manual counterpart: **Use Fastest ★** probes every profile and
moves the active one to whichever answered quickest. With *deep test* ticked that
means whichever actually carried traffic, not merely whichever had an open port.
Disabled profiles are probed but never chosen — no generated config carries them.

---

## Trojan, VMess and VLESS + TLS

None is installed by `setup.sh`, and that is deliberate: on a server you
control, Reality does Trojan's job with better camouflage and without needing a
domain or a certificate, and VMess's handshake is recognisable on the wire, which
is most of why it stopped working from China on its own.

They are here because **a subscription somebody hands you is very likely to be
one of them**, and being unable to read it made this tool useless for exactly
the case where you did not set the server up yourself. Both are modelled the
whole way through: `parseUri` reads their share links, the dashboard has fields
for them, and the Clash, Sing-Box, Surge, Quantumult X and subscription outputs
all carry them.

```bash
node gen.js --add "trojan://password@proxy.example.com:443?security=tls&sni=proxy.example.com&type=ws&path=/tj#Provider"
node gen.js --add "vmess://eyJ2IjoiMiIsInBzIjoi…"     # the base64-JSON form
node gen.js --add "vless://UUID@proxy.example.com:443?security=tls&sni=proxy.example.com&type=ws&path=/ray#Provider"
```

Both ride on `tcp`, `ws` or `grpc`. `ws` is the one that matters in practice —
it is what survives a CDN in front of the server, and the `Host` header is what
the CDN routes on, so it is not decoration.

A few things worth knowing, all of which the validator will tell you about:

- **Trojan is nothing but real TLS with a password inside it.** Its `sni` is the
  domain the certificate was actually issued for — there is no camouflage target
  to borrow. An IP address there matches no public certificate, so verification
  fails unless you also set `insecure`.
- **VMess `alterId` should be `0`.** Anything else asks for the legacy non-AEAD
  header, which current servers refuse outright.
- **VMess TLS is optional and you want it on.** Without it the payload is still
  encrypted but the handshake is not disguised at all.
- **VLESS + TLS is VLESS without Reality**: a real certificate for a real name,
  like Trojan, with a UUID instead of a password. VLESS encrypts nothing itself,
  so a `security=none` link is refused on import rather than handed to a client
  that would send everything in the clear. The Vision flow works over `tcp`
  only. Surge has no VLESS at all; Quantumult X carries it over `tcp` and `ws`.
- VMess has no agreed URI grammar. The builder emits the `vmess://base64(JSON)`
  shape every client reads; the parser also accepts the vless-style query-string
  form some tools emit.

---

## Following a provider's subscription

Pasting a provider's link imports its servers once; when the provider rotates
them, yours go stale. A **subscription source** follows the URL instead. Add one
from the dashboard's *Subscription Sources* panel or with
`node gen.js --add-source URL --name Provider`, and pick how often to refresh
(6 h to weekly). The dashboard refreshes on that schedule; on the CLI, run
`node gen.js --refresh` from cron.

What a refresh does, and does not do:

- Servers it lists are added; servers it no longer lists are removed. A server
  that stays keeps its id — so its probe history, ★ and any device-token subset
  that names it all survive — and **stays switched off if you disabled it**.
  Disable rather than delete a provider's server you do not want: a deleted one
  comes back on the next refresh.
- Your own profiles are never touched. A provider server that matches one you
  already have (same protocol, host and port) is skipped, not duplicated.
- A failed fetch, or a response with nothing usable in it, **keeps the last good
  servers** and records why on the source. Providers fail in exactly that shape,
  and an outage should not delete your servers.
- It asks as a v2rayN client, which is what makes providers answer with the
  base64 link list this tool reads rather than a Clash YAML file.
- The URL is held to the same rules as a webhook: http(s) only, never a cloud
  metadata address, and every redirect is checked the same way.

*Stop, keep servers* turns a source's servers into ordinary profiles that nothing
will refresh; *Remove with servers* takes them out along with the source.

---

## Hysteria2 bandwidth (`up` / `down`)

Hysteria2's headline feature is **Brutal**, a congestion controller that sends at
a rate you declare instead of one it infers from packet loss. That is precisely
why it survives the lossy, heavily shaped paths into China where a TCP tunnel
collapses — and it only engages when both numbers are set. A client that declares
nothing quietly falls back to BBR, which is to say to the behaviour you chose
Hysteria2 to avoid.

Set them to what your **link** can actually do, in Mbps — on the server at
install time, in the dashboard, in `servers.json`, or by importing a share link
that carries them:

```bash
PROTOCOL=hysteria2 HY2_UP=50 HY2_DOWN=200 bash setup.sh
```

`setup.sh` writes both into `profile.json` and into the URI it prints, so a
server set up this way arrives with Brutal already on. Given neither, it says so
rather than leaving you to assume otherwise, and refuses one without the other —
half a pair is not a rate, and a client handed one silently reverts to BBR.

```json
{ "protocol": "hysteria2", "up": 50, "down": 200, "…": "…" }
```

Guess **low** rather than high. A declared rate above your real capacity means
Hysteria2 keeps hammering a link that cannot take it, which is worse than not
declaring one at all. `config-gen` warns when they are missing, and emits them
as `up`/`down` for Clash.Meta and `up_mbps`/`down_mbps` for Sing-Box. The share
link carries them too — the spec says nothing about bandwidth, so a client that
ignores the extra parameters loses nothing, while a subscription that dropped
them would turn Brutal off on every device it feeds.

---

## Routing behaviour

Both generated configs route Chinese and private-network traffic direct, and
everything else through the proxy:

- **Private ranges stay direct.** Without this, your router's admin page and any
  local dev server get tunnelled to the VPS.
- **DNS uses domestic resolvers first** (223.5.5.5, 119.29.29.29), with a
  foreign resolver as *fallback* for names that come back with a non-CN address.
  This matters: rule matching can't classify a domain until it resolves, so
  putting a blocked resolver first stalls every lookup.
- **The foreign fallback goes over DoH, through the tunnel.** Google and
  Cloudflare DNS are not merely blocked from inside the firewall — a plain UDP
  query to either is *answered*, by the firewall, with whatever address it feels
  like. So the Clash config asks for them as
  `https://dns.google/dns-query#PROXY`: DoH so the query cannot be read, and
  mihomo's `#GroupName` suffix so it rides the proxy rather than the open
  internet. Sing-Box has always done this (`detour: proxy`); the Clash bundle
  used to hand the fallback out in clear text on port 53.
- **The proxy's own hostname resolves domestically, and never through itself.**
  If your server is named rather than numbered, resolving it is the one lookup
  that has to work before the tunnel exists. Clash gets
  `proxy-server-nameserver`; Sing-Box gets `route.default_domain_resolver`
  pointing at the domestic resolver (which sing-box 1.14 *requires* — without it
  the bundle refuses to start) plus a DNS rule pinning those names for apps
  inside the tunnel; and both configs add them to `fake-ip-filter` — a fake IP
  for the box you are dialling is a tunnel that never comes up.
- **Domestic sites are matched by name as well as by address.** Both bundles
  send China-listed domains direct before the GEOIP rule (Clash `GEOSITE,CN`,
  Sing-Box `geosite-cn`), which catches Chinese services on CDNs whose addresses
  are not registered in China and needs no DNS lookup to classify.
- **Your own routing rules come first.** Anything in the dashboard's *Routing
  Rules* lists is applied ahead of all of the above, in the order block → proxy →
  direct.
- **Foreign QUIC (UDP/443) is rejected**, after the CN-direct rules, so nothing
  domestic is touched. Half the protocols here cannot relay UDP at all —
  Shadowsocks + v2ray-plugin is TCP only — and Chrome opens QUIC to Google and
  YouTube by default. It gets silence rather than a refusal, and burns seconds
  per connection before retrying over TCP. The symptom is "the proxy works but
  YouTube is unusable", which is almost impossible to attribute. A `REJECT`
  makes the fallback instant.
- Clash uses `fake-ip` mode, with the usual exemptions for things that *use* the
  address they are handed rather than just connecting to it — captive-portal
  checks, NTP, STUN, consoles. Sing-Box uses remote rule-sets fetched
  **directly from the same jsDelivr mirror** the Clash geo files come from. They
  used to be fetched through the proxy, which meant a cold start — or a start
  with the selected server blocked — could not download them, and sing-box will
  not start with a remote rule-set it has never fetched.
- **Connections that arrive as a bare IP are sniffed** for the domain, so
  anything that resolved before mihomo started — or ships its own resolver — can
  still be matched on a domain rule instead of falling back to GEOIP.
- The Clash config points `geox-url` at a **jsDelivr mirror**. GEOIP/GEOSITE
  rules do nothing until the database exists, and mihomo's default download URLs
  are on GitHub — unreachable from precisely the network this config is written
  for. Clash Verge Rev and ClashX Meta ship the files, so this only matters to
  bare `mihomo`, but a first run that can't classify anything is the worst
  possible failure mode.
- The Sing-Box config carries **both a `tun` inbound and the loopback `mixed`
  one**. The mobile Sing-Box apps route system traffic through `tun`; with only
  a mixed inbound the app connects, reports itself connected, and carries
  nothing. On desktop you can keep using the mixed proxy on `127.0.0.1:2080`.

> **Sing-Box version:** the generated `singbox-config.json` targets **1.12 or
> newer** (rule-sets, route `action`s, the `mixed` inbound, and the typed DNS
> server shape — `{ "type": "https", "server": "1.1.1.1" }` rather than the
> `address:` URL string 1.12 deprecated). The older schemas it replaced — the
> `dns` outbound type, inline `geoip` route rules, separate socks/http inbounds —
> are removed in current releases. CI loads every generated bundle into a real
> sing-box and mihomo (pinned versions on each push, the latest releases weekly),
> so a change upstream shows up there before it shows up on your phone. On
> 1.14+ you will see a deprecation warning for `independent_cache` and
> `download_detour`; both still work until 1.16, and their replacements do not
> exist in 1.12, which the bundle still supports.

---

## Running the Tools on macOS (detailed)

Everything in this repo runs on a Mac. `server/setup.sh` still runs on your Linux
VPS — your Mac is only used to talk to the server (`ssh`/`scp`, both built into
macOS) and to generate the client configs with Node.js. Apple Silicon (M1–M4)
and Intel Macs both work.

### 1. Install the prerequisites

macOS already ships `ssh`, `scp`, and `bash`, so you only need **Node.js** (which
includes `npm`). Two ways:

*Option A — Homebrew (recommended if you have it or don't mind installing it):*
```bash
# Install Homebrew if you don't have it (paste into Terminal):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install Node.js (LTS):
brew install node

# Verify:
node --version    # should print v18 or newer
npm --version
```

*Option B — official installer:* download the macOS **LTS** `.pkg` from
<https://nodejs.org> and double-click it. Then open **Terminal**
(⌘-Space → "Terminal") and run `node --version` to confirm.

### 2. Get this repo onto your Mac

```bash
# If you have git:
git clone <your-repo-url> airport-tool && cd airport-tool
# Or: download the ZIP, unzip it, then in Terminal `cd` into the folder, e.g.
cd ~/Downloads/airport-tool
```

### 3. Set up the server from your Mac

```bash
# From inside the airport-tool folder:
scp server/setup.sh root@YOUR_VPS_IP:/root/
ssh root@YOUR_VPS_IP
# …now you're on the VPS:
PROTOCOL=reality bash setup.sh
```

Copy the printed profile (or `cat /etc/airport-tool/profile.json`), then type
`exit` to return to your Mac.

### 4. Generate configs on your Mac

*Web UI (easiest):*
```bash
cd web-ui
npm install
npm start
```
Open <http://localhost:3000> in Safari/Chrome, add a **VLESS + Reality** profile
with the values from step 3, and click **Save Profile**.

*Or the command line:*
```bash
cd config-gen
cp servers.json.example servers.json
open -e servers.json          # opens it in TextEdit; paste your profile, save
npm install
node gen.js                   # writes configs to config-gen/output/
open output                   # reveal the output folder in Finder
```

### 5. Connect on the Mac itself (use the proxy)

To route *this Mac's* traffic through the proxy, install a Meta-capable client and
import the generated `clash-config.yaml`:

```bash
brew install --cask clashx-meta      # or download from the link in Client Apps below
```
Open **ClashX Meta** → menu-bar icon → **Config → Import** (pick
`config-gen/output/clash-config.yaml`, or paste the Subscription URL from the web
UI) → choose your profile under the menu → enable **Set as System Proxy**.

Verify it's working: visit <https://ipinfo.io> and confirm the country is now your
VPS's, or open a normally-blocked site.

> **Gatekeeper note:** the first time you open ClashX Meta, macOS may say it's from
> an unidentified developer. Right-click the app → **Open**, or allow it under
> **System Settings → Privacy & Security**.

---

## Client Apps

Reality, Hysteria2 and TUIC all need a **Meta / Xray / Sing-Box-capable** client —
plain Clash for Windows does none of them.

| Platform | App | How to import |
|---|---|---|
| Windows | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Import clash-config.yaml or the subscription URL |
| macOS | [ClashX Meta](https://github.com/MetaCubeX/ClashX.Meta) | Import clash-config.yaml |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) ($2.99) | Scan QR code |
| iOS (free) | [Sing-Box](https://apps.apple.com/app/sing-box/id6451272673) | Import singbox-config.json |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | Scan QR code |
| Android (alt) | [Sing-Box](https://github.com/SagerNet/sing-box) | Import singbox-config.json |

All of the above handle Hysteria2 except older v2rayNG builds — if a `hysteria2://`
or `tuic://` QR won't import, use Sing-Box on that device.

Installing **sing-box on your own PC** as well is worth it even if you use Clash
day to day: it's what the web UI's *deep test* drives to prove a server actually
carries traffic.

---

## Server Management

```bash
# Reality (Xray)
systemctl status xray
journalctl -u xray -f

# Hysteria2
systemctl status hysteria-server
journalctl -u hysteria-server -f

# Shadowsocks
systemctl status shadowsocks-libev
journalctl -u shadowsocks-libev -f

# TUIC (sing-box)
systemctl status sing-box
journalctl -u sing-box -f

# Connection details saved by setup.sh (all 0600) — one file per protocol
ls /etc/airport-tool/
cat /etc/airport-tool/reality.env
cat /etc/airport-tool/reality.profile.json
cat /etc/airport-tool/profile.json      # a copy of the most recent install

# Print every installed protocol's details, with certificate expiry,
# and change nothing at all
bash setup.sh --show

# The same thing as a JSON array of client profiles, for piping into the
# generator on your PC:  … --show --json | node gen.js --add -
bash setup.sh --show --json

# Re-install, or start over
bash setup.sh                 # reuses existing keys, ports and SNI
FORCE=1 bash setup.sh         # new keys — breaks existing clients
PROTOCOL=hysteria2 bash setup.sh --uninstall   # removes only that one

# The dashboard, if you run it as a service (see "Running it as a service")
systemctl status airport-ui
journalctl -u airport-ui -f
```

> `--show` exists because "print what's installed" and "reinstall it" should not
> be the same command. A plain `bash setup.sh` is safe to repeat — it reuses
> every recorded setting — but it does restart the service.

> **Upgrading from a single `server.env`?** The first run of the new script moves
> it to `<protocol>.env` automatically and carries the keys across, so existing
> clients keep working. Nothing to do by hand.

---

## Troubleshooting

**Can't connect from China:**
- The port must be open in the **cloud provider's security group**, not just on the
  box. `setup.sh` handles the on-box firewall (ufw / firewalld / iptables); it
  cannot touch your provider's console.
- Hysteria2 and TUIC: the rule must be for **UDP**. A TCP-only rule looks right
  and fails.
- Reality: confirm `REALITY_SNI` resolves and the borrowed site really serves
  TLS 1.3 on 443 — `setup.sh` warns about this, don't ignore it.
- Reality over gRPC/XHTTP: the `serviceName` / `path` has to match the server's
  exactly. It's in `/etc/airport-tool/reality.env` as `REALITY_PATH`.
- Port hopping on: the **whole** `HY2_PORT_RANGE` must be open for UDP in the
  provider's security group, not just the listening port.
- Shadowsocks: try port 443 or 80 (less likely to be blocked).
- Use **Test All Servers** in the web UI to see which profiles are reachable, and
  tick **Deep test** to find out whether they actually carry traffic. Without it,
  Hysteria2 and TUIC show as untestable — UDP reachability can't be probed
  without speaking the protocol, so silence and a drop look identical.

**Service not starting:** `setup.sh` fails loudly instead of printing connection
details for a dead service, and dumps the log. To look again:
```bash
journalctl -u xray --no-pager -n 50   # or -u hysteria-server, -u sing-box, -u shadowsocks-libev
```

**UDP doesn't work / games and QUIC fail:** the Shadowsocks setup is `tcp_only`
on purpose — v2ray-plugin's WebSocket transport can't carry UDP, so advertising
it would just fail differently. Use Hysteria2 or TUIC if you need UDP.

**`sing-box run` fails with a permissions error on my laptop:** you have the
mobile config. Its `tun` interface needs root/Administrator — the phone apps
provide it, a desktop shell does not. Download **Sing-Box (desktop CLI)** from
the dashboard instead (or `GET /api/download/singbox?tun=0`); it listens on
`127.0.0.1:2080` and needs no privileges.

**A certificate expired:** `bash setup.sh --show` reports how long each one has
left, and so does the dashboard for any profile a TLS handshake can reach — amber
inside 14 days, red once it is past. TUIC and Shadowsocks with `DOMAIN=` install
a certbot renewal hook, so renewals are picked up automatically; Hysteria2 with
`DOMAIN=` does its own ACME. A self-signed certificate is valid for ten years and
clients skip verification anyway. Hysteria2 and TUIC serve theirs inside QUIC,
which the probes cannot speak, so those two are only datable from the server.

**Web UI returns 403 on a button press, but the page loads:** the request looked
like it came from another site. That check keys off `Sec-Fetch-Site` and
`Origin`, so it fires if something between you and the dashboard rewrites them —
a reverse proxy that sets `Origin` to its own name, most often. Either stop it
doing that, or reach the dashboard directly.

**A disabled profile is still in my client:** disabling takes it out of what the
dashboard *generates*; the client keeps whatever it was last given until it
re-polls the subscription URL or you re-import. Clients poll roughly daily.

**Notifications never arrive:** press *Send a test notification* — a webhook that
cannot be reached is reported rather than swallowed. If the test arrives but real
passes are silent, that is the intended behaviour: alerts fire on a change, not
on every pass, and neither a disabled profile nor an all-untestable pass counts
as one. Check that the monitor itself is on, that **Only after N consecutive
failed passes** is not set higher than you meant (the dashboard says
"down for 1 of the 3 passes it takes" while it is holding one back), and that the
process is still running — see
[Running it as a service](#running-it-as-a-service).

**The webhook URL is rejected:** only `http://` and `https://` are accepted, and
the cloud metadata addresses (`169.254.169.254`, `metadata.google.internal` and
friends) are refused outright — they hand out instance credentials to anything
that asks, and nobody has ever legitimately pointed a notification at one.
Loopback and LAN addresses *are* allowed: a self-hosted ntfy on the same box is
exactly what people point this at.

**My subscription URL leaked:** open the dashboard and press **Rotate
Subscription Token**. The old URL 404s immediately; re-point your clients at the
new one. The same applies to the dashboard token — unless `UI_TOKEN` pins it, in
which case change that variable and restart.

**A re-run changed my port or SNI:** it shouldn't any more — `setup.sh` restores
every recorded setting, not just the keys. If you're on an older copy of the
script, check `/etc/airport-tool/<protocol>.env` against what your clients hold.

**Installing a second protocol wiped the first:** fixed — each protocol now owns
`/etc/airport-tool/<protocol>.env`, and `--uninstall` touches only the one you
name. Older copies of the script shared a single `server.env` and truncated it on
every install, which took the previous protocol's keys with it.

**Web UI says the config file is not valid JSON:** it refuses to overwrite a file
it can't parse, so your credentials are still there. Fix the syntax in
`config-gen/servers.json` (or move it aside) and reload.

**Web UI returns 403:** you reached it through a hostname it doesn't trust. Use
`http://localhost:3000`, or set `ALLOWED_HOSTS=that.hostname`.

**Web UI returns 401:** it's bound off loopback, so it wants the dashboard token.
Open the `?ui_token=…` URL printed in the server log, or pin your own with
`UI_TOKEN=…`.

**Deep test says sing-box isn't on PATH:** install it on the machine running the
web UI, or point `SINGBOX_BIN` at the binary. The shallow TCP/TLS probe keeps
working without it.

**Test from outside China first** to verify the server works, then test from inside.

---

## Development

```bash
cd config-gen && npm test        # config model, URI parsing/building, Clash + Sing-Box output
cd config-gen && node test-cli.js  # gen.js itself: stdin import, and --test --alert
bash server/test-setup.sh        # every setup.sh path against stubbed system commands
cd web-ui && npm test            # the above, plus the API and deep-test suites
cd web-ui && node test/api.js    # auth, CRUD, import, downloads, rotation, restore, monitor
cd web-ui && node test/deep-test.js  # the deep connection probe, against a stubbed sing-box
cd config-gen && npm run test:real   # every bundle through a real sing-box and mihomo
```

`test-real-clients.js` builds a store holding every protocol and transport, with
custom rules and a server named after a group, and loads the result into the
real clients: `sing-box check` on both bundles, a few seconds of `sing-box run`
on the desktop one (some errors only surface at start-up), and `mihomo -t` on
the Clash file. It finds the binaries through `SINGBOX_BIN` / `MIHOMO_BIN` or on
`PATH`, and skips one it cannot find — except in CI, where
`REQUIRE_REAL_CLIENTS=1` makes a missing binary a failure. It exists because the
unit tests can only check what we *believe* each client wants: sing-box 1.14
refused to start every bundle naming a server by hostname, and mihomo refused
any config with a server called "Auto", while every unit test passed.

The same goes for `test-setup.sh`'s stubs of the things `setup.sh` downloads:
`tar` produces the member names the real v2ray-plugin tarballs contain,
`install` refuses a source that does not exist, `sha256sum` answers with the
pinned checksum (or a wrong one, for the tamper case), and `xray x25519` speaks
both its pre-2025 and current output. The old no-op stubs are how an install
step naming a file no tarball contains, and a key parser that broke on every
current Xray, both shipped with the suite green.

`test-setup.sh` replaces apt-get, systemctl, curl, xray, iptables and friends with
stubs and redirects every absolute path into a throwaway sandbox, so it never
touches the machine running it. It exists mainly to catch `set -e` aborts and
unbound variables — a script that only ever runs once, on a fresh VPS, is
otherwise untested until it fails in front of someone who can't debug it. It also
pins down the behaviour that matters most on a re-run: that a bare
`bash setup.sh` leaves the port and SNI exactly where they were.

`test/api.js` boots the real server and walks the API. Most of what can go wrong
in a credential admin panel is a route that forgets to be guarded, so it asserts
that **every** credential-bearing endpoint 401s without the dashboard token once
the UI is off loopback — and, since a token is no help when the browser attaches
it for you, that every write route refuses a cross-site request while the
dashboard's own requests, `curl`, and a client polling the subscription feed all
still work. It also covers enable/disable, per-device tokens, webhook delivery
against a local receiver, and TLS against a certificate it mints with `openssl`.

It also pins down a handful of things that were each wrong once: that the
hardening headers are actually sent, that an unknown `/api` route answers in JSON
rather than an HTML error page, that a one-character `UI_TOKEN` stops the server
instead of pretending to guard it, that a disabled ★ is refused by
`/api/qrcode` and `/api/download/uri` rather than served (the bundle endpoints
always refused, so the same store answered two different ways), that a newline
cannot be smuggled into the `profile-title` header, and that the alert threshold
holds a transition without losing it — including across a restart.

The dashboard is one self-contained HTML file with no build step, so nothing else
here would catch a `$('id')` that names an element the markup no longer has. CI
parses the inline script and cross-checks every element reference, download
button and copy target against the markup.

`test-setup.sh`'s `iptables` stub *validates* what it is handed rather than
accepting everything: a port range is written with a colon, and the firewalld
spelling is rejected the way the real tool rejects it. An accept-anything stub is
why port hopping shipped for a while handing ufw and iptables a range they both
refused, while the script printed "Opened".

`test/deep-test.js` runs the deep probe against a stubbed sing-box and a local
origin, covering config generation, port allocation, spawn, the proxied fetch,
cleanup, and the "the proxy refused to start" branch — none of which needs a real
server to be meaningful.

`test-setup.sh` also checks that its two port-range parsers — the shell one in
`setup.sh` and `normalizePortRange` in `config-gen` — accept and reject exactly
the same set. They used to disagree: the shell side took only a single `a-b`
pair while the client side happily emitted comma-separated lists, so a range set
in the dashboard reached every client while the server installed no NAT rule for
any of it, and every hop aimed at a port with nothing behind it.

All of these, plus `shellcheck`, `npm audit`, the dashboard page check and a
`docker build`, run in CI on every push — and weekly against the latest sing-box
and mihomo releases.
