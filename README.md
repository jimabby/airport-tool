# Airport Tool

Personal Shadowsocks proxy setup for use in China.
Protocol: **Shadowsocks-libev + v2ray-plugin (WebSocket)** — very resistant to deep packet inspection.

---

## Project Structure

```
airport-tool/
├── server/
│   └── setup.sh          # Run on your VPS to install the server
├── config-gen/
│   ├── gen.js             # CLI tool: generates all client configs + QR code
│   ├── server.json        # Your server details (create from .example)
│   └── server.json.example
└── web-ui/
    ├── server.js          # Express web server
    └── public/index.html  # Dashboard UI
```

---

## Step 1 — Get a Free / Cheap VPS

| Provider | Free tier | Cheapest paid | Best region for China |
|---|---|---|---|
| **Oracle Cloud** | Always-free ARM (1 OCPU, 1 GB RAM) | — | Tokyo / Osaka / Singapore |
| **Vultr** | — | $2.50/mo (IPv6) / $6/mo | Tokyo, Singapore |
| **DigitalOcean** | — | $6/mo | Singapore, San Francisco |
| **AWS Lightsail** | 3 months free | $3.50/mo | Tokyo, Singapore |

**Recommended:** Oracle Cloud Free Tier (Tokyo) — it's completely free forever.

Steps:
1. Sign up at cloud.oracle.com
2. Create a **VM.Standard.A1.Flex** instance (ARM, free)
3. Choose **Ubuntu 22.04**
4. Open port **8388/tcp** in the Security List (Networking → VCNs → Security Lists)
5. Note the public IP

---

## Step 2 — Set Up the Server

SSH into your VPS, then run:

```bash
# Option A: one-liner (with custom settings)
SS_PORT=8388 SS_PASSWORD="your-strong-password" bash <(curl -sL https://raw.githubusercontent.com/you/airport-tool/main/server/setup.sh)

# Option B: clone and run manually
git clone https://github.com/you/airport-tool
cd airport-tool
sudo bash server/setup.sh
```

The script will:
- Install `shadowsocks-libev` and `v2ray-plugin`
- Write `/etc/shadowsocks-libev/config.json`
- Enable and start the systemd service
- Open the firewall port
- Print your SS URI

---

## Step 3 — Generate Client Configs (on your PC)

```bash
cd config-gen
cp server.json.example server.json
# Edit server.json with your server IP, port, and password
npm install
node gen.js
# Or point at a different config file:
node gen.js --config /path/to/other.json
```

Output in `config-gen/output/`:
- `clash-config.yaml` — for Clash for Windows / ClashX (macOS)
- `singbox-config.json` — for Sing-Box (iOS / Android)
- `mobile-ss-uri.txt` — raw SS URI to paste or scan
- `qrcode.png` — scan with your phone

---

## Step 4 — Web UI (optional, run locally)

```bash
cd web-ui
npm install
npm start
# Open http://localhost:3000
```

Features:
- Enter / update server config in the browser
- View live QR code (scan with phone)
- Download Clash, Sing-Box, and URI configs
- View connection details at a glance
- **Test Connection** — checks that the server port is reachable (TCP reachability only)

The UI binds to `127.0.0.1` by default since the config holds your proxy
password. To expose it on your LAN, set `HOST=0.0.0.0` (you'll see a warning).

---

## Client Apps

| Platform | App | How to import |
|---|---|---|
| Windows | [Clash for Windows](https://github.com/Fndroid/clash_for_windows_pkg) | Profiles → import clash-config.yaml |
| macOS | [ClashX](https://github.com/yichengchen/clashX) | Config → import clash-config.yaml |
| iOS | [Shadowrocket](https://apps.apple.com/app/shadowrocket/id932747118) ($2.99) | Scan QR code |
| iOS (free) | [Sing-Box](https://apps.apple.com/app/sing-box/id6451272673) | Import singbox-config.json |
| Android | [v2rayNG](https://github.com/2dust/v2rayNG) | Scan QR code |
| Android (alt) | [Sing-Box](https://github.com/SagerNet/sing-box) | Import singbox-config.json |

---

## Server Management

```bash
# Check status
systemctl status shadowsocks-libev

# Restart
sudo systemctl restart shadowsocks-libev

# View logs
journalctl -u shadowsocks-libev -f

# Change password (edit config then restart)
sudo nano /etc/shadowsocks-libev/config.json
sudo systemctl restart shadowsocks-libev
```

---

## Troubleshooting

**Can't connect from China:**
- Make sure port 8388/tcp is open in your VPS firewall AND your cloud provider's security group/ACL
- Try changing the port to 443 or 80 (less likely to be blocked)
- Oracle Cloud: also check the instance's iptables — Oracle adds its own rules

**Service not starting:**
```bash
journalctl -u shadowsocks-libev --no-pager -n 50
```

**Test from outside China first** to verify the server works, then test from inside.
