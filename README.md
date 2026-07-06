# Airport Tool

Personal proxy setup for use in China. Two protocols, one toolchain:

- **Shadowsocks-libev + v2ray-plugin (WebSocket, optional TLS)** — simple, battle-tested.
- **VLESS + Reality (Xray)** — TLS camouflage that borrows a real site's handshake. **The most DPI-resistant option** and the recommended default in 2026.

The server script, config generator, and web UI all understand both protocols and let you manage **multiple server profiles** at once.

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

SSH into your VPS, then pick a protocol:

```bash
# VLESS + Reality (recommended — most DPI-resistant)
PROTOCOL=reality bash <(curl -sL https://raw.githubusercontent.com/you/airport-tool/main/server/setup.sh)

# Shadowsocks + v2ray-plugin (WebSocket)
SS_PORT=8388 SS_PASSWORD="strong-pw" bash <(curl -sL .../server/setup.sh)

# Shadowsocks with real TLS (needs a domain pointed at the server)
DOMAIN=proxy.example.com V2RAY_PLUGIN_MODE=tls bash <(curl -sL .../server/setup.sh)
```

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
