# Airport Tool

Personal proxy setup for use in China. Four protocols, one toolchain:

- **VLESS + Reality (Xray)** — TLS camouflage that borrows a real site's handshake. **The most DPI-resistant option** and the recommended default in 2026. Rides on raw TCP, gRPC or XHTTP.
- **Hysteria2 (QUIC/UDP)** — holds up best on lossy, heavily-shaped paths, and relays UDP. Good second server / failover.
- **TUIC v5 (QUIC/UDP)** — the same loss tolerance and real UDP relay as Hysteria2, without Hysteria2's distinctive congestion behaviour, which some ISPs shape on sight.
- **Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)** — simple, battle-tested, TCP only.

The server script, config generator, and web UI all understand every protocol and
let you manage **multiple server profiles** at once, with automatic failover between
them.

| | Reality | Hysteria2 | TUIC v5 | Shadowsocks |
|---|---|---|---|---|
| Transport | TCP / gRPC / XHTTP | UDP (QUIC) | UDP (QUIC) | TCP |
| Relays UDP for you | yes | yes | yes | **no** |
| On a lossy link | good | **best** | very good | poor |
| Blocked-port risk | low (looks like HTTPS) | some ISPs throttle UDP | some ISPs throttle UDP | medium |
| Port hopping | — | **yes** (`HY2_PORT_RANGE`) | — | — |
| Needs a domain | no | no (self-signed) | no (self-signed) | only for TLS mode |

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
| Windows | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Import `clash-config.yaml` or paste the Subscription URL |
| macOS | [ClashX Meta](https://github.com/MetaCubeX/ClashX.Meta) | Import `clash-config.yaml` |

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
│   ├── lib/probe.js          # Shared connectivity probes (tcp / tls / deep)
│   ├── lib/history.js        # Shared probe-history file
│   ├── test.js               # Tests for the above (npm test)
│   ├── servers.json          # Your profiles + subscription token (create from .example)
│   └── servers.json.example
└── web-ui/
    ├── server.js             # Express web server + REST API + subscription endpoint
    ├── public/index.html     # Dashboard UI
    └── test/
        ├── api.js            # Auth, CRUD, import, downloads, rotation, restore, monitor
        ├── deep-test.js      # The deep connection probe, end to end
        └── fake-sing-box.js  # Stand-in binary the deep test drives
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

# TUIC v5 (UDP/QUIC, served by sing-box)
PROTOCOL=tuic bash setup.sh

# Shadowsocks + v2ray-plugin (WebSocket)
SS_PORT=8388 SS_PASSWORD="strong-pw" bash setup.sh

# Shadowsocks with real TLS (needs a domain pointed at the server)
DOMAIN=proxy.example.com V2RAY_PLUGIN_MODE=tls bash setup.sh
```

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
and a UDP protocol can share a number. `--show` reports how long each
certificate has left, which is the failure that otherwise happens quietly while
you are not looking.

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

# Or set it up by hand
cp servers.json.example servers.json
# Edit servers.json: paste the profile(s) from /etc/airport-tool/profile.json
node gen.js

# Point at another file: node gen.js --config /path/to/other.json
# Back the whole store up somewhere safe and stop:
node gen.js --export ~/backups/servers.json

# Probe every server and stop, without regenerating anything:
node gen.js --test
node gen.js --test --deep      # dial through each one with a local sing-box
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
a monitoring check. `--deep` is the only mode that says anything about a QUIC
profile, and the only one that proves the credentials work.

`--add` accepts a share link, several links on separate lines, a base64
subscription blob (standard or URL-safe alphabet), or a JSON profile. Duplicates
(same protocol + server + port) are skipped rather than added twice.

Output in `config-gen/output/`:
- `clash-config.yaml` — Clash.Meta / Mihomo (all profiles)
- `singbox-config.json` — Sing-Box (all profiles, with a selector)
- `subscription-base64.txt` — subscription blob (all profiles)
- `uris.txt` — every profile's import URI
- `active-uri.txt` + `qrcode.png` — the active profile, ready to scan

`servers.json` holds **multiple profiles**; `active` is the index of the one used
for the QR code. A single legacy `server.json` object still works.

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
- **Four protocols**: Reality (TCP/gRPC/XHTTP), Hysteria2, TUIC v5 and Shadowsocks, with protocol-aware fields
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
- Download Clash.Meta, Sing-Box and URI configs — plus **Backup `servers.json`**
  and **Restore from Backup**, which puts back the profiles *and* both tokens, so
  subscription URLs you already handed out start working again
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
    a wrapper).
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

### Security of the local UI

The dashboard is an admin panel for a file full of proxy credentials, so it takes
several precautions:

- It binds to `127.0.0.1` by default. `HOST=0.0.0.0` exposes it on your LAN.
- It rejects requests whose `Host` header is a **hostname** it doesn't expect,
  which is what stops a web page you visit from reaching it via DNS rebinding.
  `localhost` and bare IP addresses are allowed; if you reach the UI through a
  DDNS name, permit it with `ALLOWED_HOSTS=my.name.example`.
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
- The **subscription URL carries its own, separate token**
  (`/api/subscription/<token>`), because a client polling that feed can hold
  neither a cookie nor a header. Keeping the two apart means handing a phone the
  subscription URL does not also hand it write access to every profile. Treat it
  as a password. Both tokens live in `servers.json`; delete `token` or `uiToken`
  and restart to roll either one.
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

---

## Failover

With two or more profiles, the generated configs include an automatic
lowest-latency group — `Auto` (`url-test`) in Clash, `auto` (`urltest`) in
Sing-Box — checked every few minutes against `generate_204`. Select it once and a
server that gets blocked drops out on its own. Single-profile configs skip the
group, since there's nothing to fail over to.

The best pairing is **two different protocols on two different providers**: a
Reality box and a Hysteria2 (or TUIC) box fail for different reasons, so one
blocking event rarely takes out both.

The web UI has a manual counterpart: **Use Fastest ★** probes every profile and
moves the active one to whichever answered quickest. With *deep test* ticked that
means whichever actually carried traffic, not merely whichever had an open port.

---

## Routing behaviour

Both generated configs route Chinese and private-network traffic direct, and
everything else through the proxy:

- **Private ranges stay direct.** Without this, your router's admin page and any
  local dev server get tunnelled to the VPS.
- **DNS uses domestic resolvers first** (223.5.5.5, 119.29.29.29) with 8.8.8.8 /
  1.1.1.1 as *fallback* for names that resolve to non-CN addresses. This matters:
  Google and Cloudflare DNS are blocked from inside the firewall, and rule
  matching can't classify a domain until it resolves — putting them first stalls
  every lookup.
- Clash uses `fake-ip` mode; Sing-Box uses remote rule-sets fetched **through the
  proxy** (they're unreachable directly from where this config gets used).
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

> **Sing-Box version:** the generated `singbox-config.json` targets **1.11 or
> newer** (rule-sets, route `action`s, the `mixed` inbound). The older schema it
> replaced — the `dns` outbound type, inline `geoip` route rules, separate
> socks/http inbounds — is deprecated upstream and removed in current releases.
> Check your client's version if it rejects the config.

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

# Re-install, or start over
bash setup.sh                 # reuses existing keys, ports and SNI
FORCE=1 bash setup.sh         # new keys — breaks existing clients
PROTOCOL=hysteria2 bash setup.sh --uninstall   # removes only that one
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
left. TUIC and Shadowsocks with `DOMAIN=` install a certbot renewal hook, so
renewals are picked up automatically; Hysteria2 with `DOMAIN=` does its own ACME.
A self-signed certificate is valid for ten years and clients skip verification
anyway.

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
bash server/test-setup.sh        # every setup.sh path against stubbed system commands
cd web-ui && npm test            # the above, plus the API and deep-test suites
cd web-ui && node test/api.js    # auth, CRUD, import, downloads, rotation, restore, monitor
cd web-ui && node test/deep-test.js  # the deep connection probe, against a stubbed sing-box
```

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
the UI is off loopback.

`test/deep-test.js` runs the deep probe against a stubbed sing-box and a local
origin, covering config generation, port allocation, spawn, the proxied fetch,
cleanup, and the "the proxy refused to start" branch — none of which needs a real
server to be meaningful.

All four suites, plus `shellcheck` and `npm audit`, run in CI on every push.
