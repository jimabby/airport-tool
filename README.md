# Airport Tool

Personal proxy setup for use in China. Three protocols, one toolchain:

- **VLESS + Reality (Xray)** — TLS camouflage that borrows a real site's handshake. **The most DPI-resistant option** and the recommended default in 2026.
- **Hysteria2 (QUIC/UDP)** — holds up best on lossy, heavily-shaped paths, and is the only one here that actually relays UDP. Good second server / failover.
- **Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)** — simple, battle-tested, TCP only.

The server script, config generator, and web UI all understand every protocol and
let you manage **multiple server profiles** at once, with automatic failover between
them.

| | Reality | Hysteria2 | Shadowsocks |
|---|---|---|---|
| Transport | TCP | UDP (QUIC) | TCP |
| Relays UDP for you | yes | yes | **no** |
| On a lossy link | good | **best** | poor |
| Blocked-port risk | low (looks like HTTPS) | some ISPs throttle UDP | medium |
| Needs a domain | no | no (self-signed) | only for TLS mode |

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
│   ├── setup.sh              # Run on your VPS. PROTOCOL=reality|hysteria2|shadowsocks
│   └── test-setup.sh         # Smoke-tests setup.sh against stubbed system commands
├── config-gen/
│   ├── gen.js                # CLI: generates all client configs + QR + subscription
│   ├── lib/configs.js        # Shared model + builders (protocols, URIs, Clash, Sing-Box)
│   ├── test.js               # Tests for the above (npm test)
│   ├── servers.json          # Your profiles + subscription token (create from .example)
│   └── servers.json.example
└── web-ui/
    ├── server.js             # Express web server + REST API + subscription endpoint
    └── public/index.html     # Dashboard UI
```

`config-gen/servers.json` is the single source of truth — the CLI and the web UI
share it. It holds your proxy passwords **and** the subscription token, so it is
written `0600` and is in `.gitignore`. Never commit it.

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

# Hysteria2 (UDP/QUIC — best on a lossy link, and relays UDP)
PROTOCOL=hysteria2 bash setup.sh

# Hysteria2 with a real certificate instead of a self-signed one
PROTOCOL=hysteria2 DOMAIN=proxy.example.com bash setup.sh

# Shadowsocks + v2ray-plugin (WebSocket)
SS_PORT=8388 SS_PASSWORD="strong-pw" bash setup.sh

# Shadowsocks with real TLS (needs a domain pointed at the server)
DOMAIN=proxy.example.com V2RAY_PLUGIN_MODE=tls bash setup.sh
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
bash setup.sh --uninstall     # stops the service, removes configs, closes the port
bash setup.sh --help
```

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

# Or set it up by hand
cp servers.json.example servers.json
# Edit servers.json: paste the profile(s) from /etc/airport-tool/profile.json
node gen.js

# Point at another file: node gen.js --config /path/to/other.json
```

`--add` accepts a share link, several links on separate lines, a base64
subscription blob, or a JSON profile. Duplicates (same protocol + server + port)
are skipped rather than added twice.

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
- **Three protocols**: Reality, Hysteria2 and Shadowsocks, with protocol-aware fields
- **Import** — paste a share link, several links, a subscription blob, or the
  server's `profile.json`, instead of retyping six fields
- **Generate** buttons for strong passwords and UUIDs
- Live QR code (scan with phone)
- **Subscription URL** for auto-updating clients — token-gated (see below)
- Download Clash.Meta, Sing-Box, and URI configs
- **Test Connection** — TCP reachability, plus a real **TLS handshake** with the
  configured SNI for Reality / TLS profiles (does the port actually speak TLS?)
- **Test All Servers** — probes every profile at once and ranks them by latency,
  so you can see which server to be on right now

### Security of the local UI

The dashboard is an unauthenticated admin panel for a file full of proxy
credentials, so it takes a few precautions:

- It binds to `127.0.0.1` by default. `HOST=0.0.0.0` exposes it on your LAN.
- It rejects requests whose `Host` header is a **hostname** it doesn't expect,
  which is what stops a web page you visit from reaching it via DNS rebinding.
  `localhost` and bare IP addresses are allowed; if you reach the UI through a
  DDNS name, permit it with `ALLOWED_HOSTS=my.name.example`.
- The **subscription URL carries a secret token** (`/api/subscription/<token>`).
  The response is literally every credential you own, so an open path would hand
  them to anyone who could reach the port — exactly the situation you create the
  moment you set `HOST=0.0.0.0` so your phone can subscribe. Treat the URL as a
  password. The token lives in `servers.json`; delete the `token` field and
  restart to roll it (every subscribed client then needs the new URL).

If `servers.json` is ever unparseable, the UI refuses to read **or** write it and
shows the error, rather than starting from an empty store and overwriting your
credentials on the next save.

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
Reality box and a Hysteria2 box fail for different reasons, so one blocking event
rarely takes out both.

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

Reality and Hysteria2 both need a **Meta / Xray / Sing-Box-capable** client —
plain Clash for Windows does neither.

| Platform | App | How to import |
|---|---|---|
| Windows | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Import clash-config.yaml or the subscription URL |
| macOS | [ClashX Meta](https://github.com/MetaCubeX/ClashX.Meta) | Import clash-config.yaml |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) ($2.99) | Scan QR code |
| iOS (free) | [Sing-Box](https://apps.apple.com/app/sing-box/id6451272673) | Import singbox-config.json |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | Scan QR code |
| Android (alt) | [Sing-Box](https://github.com/SagerNet/sing-box) | Import singbox-config.json |

All of the above handle Hysteria2 except older v2rayNG builds — if a `hysteria2://`
QR won't import, use Sing-Box on that device.

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

# Connection details saved by setup.sh (both 0600)
cat /etc/airport-tool/server.env
cat /etc/airport-tool/profile.json

# Re-print without changing anything, or start over
bash setup.sh                 # reuses existing keys
FORCE=1 bash setup.sh         # new keys — breaks existing clients
bash setup.sh --uninstall
```

---

## Troubleshooting

**Can't connect from China:**
- The port must be open in the **cloud provider's security group**, not just on the
  box. `setup.sh` handles the on-box firewall (ufw / firewalld / iptables); it
  cannot touch your provider's console.
- Hysteria2: the rule must be for **UDP**. A TCP-only rule looks right and fails.
- Reality: confirm `REALITY_SNI` resolves and the borrowed site really serves
  TLS 1.3 on 443 — `setup.sh` warns about this, don't ignore it.
- Shadowsocks: try port 443 or 80 (less likely to be blocked).
- Use **Test All Servers** in the web UI to see which profiles are reachable.
  Hysteria2 shows as untestable — UDP reachability can't be probed without
  speaking the protocol, so silence and a drop look identical.

**Service not starting:** `setup.sh` now fails loudly instead of printing
connection details for a dead service, and dumps the log. To look again:
```bash
journalctl -u xray --no-pager -n 50   # or -u hysteria-server, -u shadowsocks-libev
```

**UDP doesn't work / games and QUIC fail:** the Shadowsocks setup is `tcp_only`
on purpose — v2ray-plugin's WebSocket transport can't carry UDP, so advertising
it would just fail differently. Use Hysteria2 if you need UDP.

**Web UI says the config file is not valid JSON:** it refuses to overwrite a file
it can't parse, so your credentials are still there. Fix the syntax in
`config-gen/servers.json` (or move it aside) and reload.

**Web UI returns 403:** you reached it through a hostname it doesn't trust. Use
`http://localhost:3000`, or set `ALLOWED_HOSTS=that.hostname`.

**Test from outside China first** to verify the server works, then test from inside.

---

## Development

```bash
cd config-gen && npm test     # config model, URI parsing/building, Clash + Sing-Box output
bash server/test-setup.sh     # runs every setup.sh path against stubbed system commands
```

`test-setup.sh` replaces apt-get, systemctl, curl, xray, iptables and friends with
stubs and redirects every absolute path into a throwaway sandbox, so it never
touches the machine running it. It exists mainly to catch `set -e` aborts and
unbound variables — a script that only ever runs once, on a fresh VPS, is
otherwise untested until it fails in front of someone who can't debug it. Both
suites plus `shellcheck` run in CI on every push.
