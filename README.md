# Airport Tool

Personal proxy setup for use in China. Two protocols, one toolchain:

- **Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)** — simple, battle-tested.
- **VLESS + Reality (Xray)** — TLS camouflage that borrows a real site's handshake. **The most DPI-resistant option** and the recommended default in 2026.

The server script, config generator, and web UI all understand both protocols and let you manage **multiple server profiles** at once.

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
Open <http://localhost:3000>, click **+ New Profile**, choose **VLESS + Reality**,
and fill in the Server IP / Port / UUID / Public Key / Short ID / SNI from step 2.
Click **Save Profile**. A QR code and a **Subscription URL** appear.

*Option B — command line:*
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
│   └── setup.sh              # Run on your VPS. PROTOCOL=shadowsocks|reality
├── config-gen/
│   ├── gen.js                # CLI: generates all client configs + QR + subscription
│   ├── lib/configs.js        # Shared model + builders (protocols, URIs, Clash, Sing-Box)
│   ├── servers.json          # Your profiles (create from .example)
│   └── servers.json.example
└── web-ui/
    ├── server.js             # Express web server + REST API + subscription endpoint
    └── public/index.html     # Dashboard UI
```

---

## Step 1 — Get a Free / Cheap VPS

| Provider | Free tier | Cheapest paid | Best region for China |
|---|---|---|---|
| **Oracle Cloud** | Always-free ARM (1 OCPU, 1 GB RAM) | — | Tokyo / Osaka / Singapore |
| **Vultr** | — | $2.50/mo (IPv6) / $6/mo | Tokyo, Singapore |
| **DigitalOcean** | — | $6/mo | Singapore, San Francisco |
| **AWS Lightsail** | 3 months free | $3.50/mo | Tokyo, Singapore |

**Recommended:** Oracle Cloud Free Tier (Tokyo) — free forever. For Reality, open **443/tcp**; for Shadowsocks, open **8388/tcp** (or 443).

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

# Shadowsocks + v2ray-plugin (WebSocket)
SS_PORT=8388 SS_PASSWORD="strong-pw" bash setup.sh

# Shadowsocks with real TLS (needs a domain pointed at the server)
DOMAIN=proxy.example.com V2RAY_PLUGIN_MODE=tls bash setup.sh
```

> If you host this repo on GitHub yourself, you can instead pipe it in one line —
> replace `YOUR_GH_USER` with your username:
> `PROTOCOL=reality bash <(curl -sL https://raw.githubusercontent.com/YOUR_GH_USER/airport-tool/main/server/setup.sh)`

The script installs everything, enables the systemd service, opens the firewall,
prints the connection details, and — importantly — writes a ready-to-import
profile to **`/etc/airport-tool/profile.json`**. Copy that object into the
`profiles` array of `config-gen/servers.json`.

**Env knobs:** `PROTOCOL` (`shadowsocks`|`reality`), `SS_PORT`, `SS_PASSWORD`,
`SS_METHOD`, `DOMAIN`, `V2RAY_PLUGIN_MODE`, `REALITY_PORT`, `REALITY_SNI`.

For Reality, the script auto-generates the x25519 keypair, UUID and short ID via
`xray`, and camouflages behind `REALITY_SNI` (default `www.microsoft.com`).

---

## Step 3 — Generate Client Configs (on your PC)

```bash
cd config-gen
cp servers.json.example servers.json
# Edit servers.json: paste the profile(s) from /etc/airport-tool/profile.json
npm install
node gen.js
# Or point at another file: node gen.js --config /path/to/other.json
```

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
- **Two protocols**: Shadowsocks and VLESS + Reality, with protocol-aware fields
- **Generate** buttons for strong passwords and UUIDs
- Live QR code (scan with phone)
- **Subscription URL** for auto-updating clients (`/api/subscription`)
- Download Clash.Meta, Sing-Box, and URI configs
- **Test Connection** — TCP reachability, plus a real **TLS handshake** with the
  configured SNI for Reality / TLS profiles (does the port actually speak TLS?)

The UI binds to `127.0.0.1` by default since the config holds proxy secrets. To
expose it on your LAN, set `HOST=0.0.0.0` (you'll see a warning).

> **Note on Shadowsocks `plugin_opts`:** keep the `server` keyword in your
> profile (it describes the *server*). Client configs strip `server` and any
> `cert=`/`key=` automatically — a client must not run the plugin in server mode.
> Leave the WebSocket path empty to use the default (`/`).

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

Reality needs a **Meta/Xray-capable** client (plain Clash for Windows won't do VLESS).

| Platform | App | How to import |
|---|---|---|
| Windows | [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) | Import clash-config.yaml or the subscription URL |
| macOS | [ClashX Meta](https://github.com/MetaCubeX/ClashX.Meta) | Import clash-config.yaml |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) ($2.99) | Scan QR code |
| iOS (free) | [Sing-Box](https://apps.apple.com/app/sing-box/id6451272673) | Import singbox-config.json |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | Scan QR code |
| Android (alt) | [Sing-Box](https://github.com/SagerNet/sing-box) | Import singbox-config.json |

---

## Server Management

```bash
# Shadowsocks
systemctl status shadowsocks-libev
journalctl -u shadowsocks-libev -f

# Reality (Xray)
systemctl status xray
journalctl -u xray -f

# Connection details saved by setup.sh
cat /etc/airport-tool/server.env
cat /etc/airport-tool/profile.json
```

---

## Troubleshooting

**Can't connect from China:**
- Make sure the port is open in your VPS firewall AND the cloud provider's security group.
- Reality: confirm `REALITY_SNI` resolves and the borrowed site actually serves TLS on 443.
- Shadowsocks: try port 443 or 80 (less likely to be blocked).
- Oracle Cloud: also check the instance's iptables — Oracle adds its own rules.

**Service not starting:**
```bash
journalctl -u shadowsocks-libev --no-pager -n 50   # or -u xray
```

**Test from outside China first** to verify the server works, then test from inside.
