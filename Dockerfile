# The dashboard (and with it the background health monitor) as a container.
#
# The systemd unit in web-ui/ is the right answer on a Linux box you already
# own. This is for everywhere else — a NAS, a laptop, a spare VPS — and for the
# case the unit cannot help with: the monitor only notices an outage while the
# process is running, and `npm start` in a terminal dies with the terminal.
#
# Everything runs as the unprivileged `node` user. The image needs no capability
# beyond reading and writing one directory, because that is all the dashboard
# does: /data holds servers.json and, beside it, the probe history, the monitor
# state and (with TLS_SELFSIGNED=1) the dashboard certificate.
#
#   docker compose up -d          # then read the log for the dashboard URL
#   docker compose logs dashboard
#
# sing-box is included so the deep connection test — and a deep health monitor —
# work out of the box. It is the only check that proves a server's credentials
# work, and the only one that says anything at all about Hysteria2 and TUIC,
# which a container user had no easy way to add. It is copied from the upstream
# image, pinned by version; build with --build-arg SINGBOX_VERSION=… to change it.
#
# Node 24 is the current LTS line. 20 reached end of life in April 2026 and no
# longer gets security fixes, which is not what a process holding every proxy
# credential should run on.

ARG SINGBOX_VERSION=1.14.2
FROM ghcr.io/sagernet/sing-box:v${SINGBOX_VERSION} AS singbox

FROM node:24-alpine AS deps
WORKDIR /app
# Only the manifests first, so a source-only change does not reinstall.
COPY web-ui/package.json web-ui/package-lock.json ./
# `npm ci`, not `install`: the lockfile is committed, and an image that quietly
# resolved a different tree is not the one that was tested.
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:24-alpine

# openssl mints the certificate for TLS_SELFSIGNED=1. Node has no API that can,
# and setup.sh already depends on openssl, so it is the one generator this
# project can count on.
RUN apk add --no-cache openssl

WORKDIR /app

# node_modules sits at /app rather than /app/web-ui on purpose: Node's
# resolution walks upwards, so one copy serves both web-ui/server.js and
# config-gen/gen.js. They depend on the same two packages.
COPY --from=deps /app/node_modules ./node_modules

# Only what actually runs. No tests, no examples, no .git.
COPY web-ui/server.js ./web-ui/server.js
COPY web-ui/public ./web-ui/public
COPY config-gen/lib ./config-gen/lib
COPY config-gen/gen.js ./config-gen/gen.js

# The deep test's proxy. probe.js finds it on PATH.
COPY --from=singbox /usr/local/bin/sing-box /usr/local/bin/sing-box

# The one writable location. Everything stateful is derived from CFG_PATH:
# test-history.json, monitor-state.json and the TLS pair all land beside it.
RUN mkdir -p /data && chown node:node /data
VOLUME ["/data"]
ENV CFG_PATH=/data/servers.json \
    HOST=0.0.0.0 \
    PORT=3000 \
    NODE_ENV=production

# Reachable from outside the container means not loopback, which means the
# dashboard will demand its token — see the AUTH_REQUIRED note in server.js.
EXPOSE 3000

USER node

# 401 is a healthy answer here: off loopback the dashboard requires a token, and
# refusing an unauthenticated request is the server working correctly. Only a
# connection failure or a 5xx means something is actually wrong.
#
# Both ways of turning TLS on count. This used to look only at TLS_SELFSIGNED,
# so a container given its own certificate through TLS_CERT/TLS_KEY spoke plain
# HTTP to its HTTPS listener and was reported unhealthy for ever.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const e=process.env;const tls=e.TLS_SELFSIGNED==='1'||!!(e.TLS_CERT&&e.TLS_KEY); \
    const r=require(tls?'https':'http').request({host:'127.0.0.1',port:e.PORT||3000,path:'/',rejectUnauthorized:false}, \
    (s)=>process.exit(s.statusCode<500?0:1)); r.on('error',()=>process.exit(1)); r.end();"

CMD ["node", "web-ui/server.js"]
