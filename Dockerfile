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
# The deep connection test needs a sing-box binary, which is deliberately not in
# here — it would double the image for a feature many people never switch on.
# To enable it, either mount one in and point SINGBOX_BIN at it, or add a line
# to this file installing it and rebuild.

FROM node:20-alpine AS deps
WORKDIR /app
# Only the manifests first, so a source-only change does not reinstall.
COPY web-ui/package.json web-ui/package-lock.json ./
# `npm ci`, not `install`: the lockfile is committed, and an image that quietly
# resolved a different tree is not the one that was tested.
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:20-alpine

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
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const m=process.env.TLS_SELFSIGNED==='1'?require('https'):require('http'); \
    const r=m.request({host:'127.0.0.1',port:process.env.PORT||3000,path:'/',rejectUnauthorized:false}, \
    (s)=>process.exit(s.statusCode<500?0:1)); r.on('error',()=>process.exit(1)); r.end();"

CMD ["node", "web-ui/server.js"]
