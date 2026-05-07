# Lemmy + lemmy-ui + Postgres + an OIDC-bridge sidecar packaged
# as a single OpenHost-deployable container.
#
# Layout:
#
#   browser → OpenHost router (subdomain lemmy.<zone>; verifies
#                              owner zone_auth, stamps
#                              X-OpenHost-Is-Owner)
#          → container :8080  (nginx)
#                ├─ /_oidc/*  → OIDC bridge (Python on :7000)
#                ├─ /api/*    → Lemmy backend (:8536)
#                ├─ /pictrs/* → Lemmy backend (:8536)
#                ├─ /sso-bounce → OIDC-redirect HTML page (the
#                                bouncer; written by nginx itself
#                                as a tiny inline HTML doc)
#                └─ /         → bouncer logic (when owner +
#                              no Lemmy session) or lemmy-ui
#                              (:1234) for everything else.
#
# Internal services launched by start.sh (no s6, just bash with
# `wait -n` like the openhost-sftp/syncthing/joplin pattern):
#
#   * postgres (15) — Lemmy's metadata DB.  Data dir under
#                     $OPENHOST_APP_DATA_DIR/postgres.
#   * lemmy_server  — the Rust API + ActivityPub backend.
#                     Reads $LEMMY_CONFIG_LOCATION.
#   * lemmy-ui      — Node SSR frontend (lemmy-ui/dist).
#   * oidc-bridge   — Python Starlette OIDC provider using the
#                     same shape as openhost-immich.
#   * nginx         — request router on :8080.

# Stage 1: lemmy-ui binaries.
# We pin Lemmy 1.0.0-alpha.18 (released 2026-05-04) because OAuth/
# OIDC support — required for our SSO flow — landed only in the
# 1.0 series; 0.19.x does not expose the /api/v3/oauth_provider
# endpoint we need.  See LemmyNet/lemmy#4881.
FROM dessalines/lemmy-ui:1.0.0-alpha.18 AS ui-source

# Stage 2: lemmy backend.
FROM dessalines/lemmy:1.0.0-alpha.18 AS backend-source

# Stage 3: final image.  Debian bookworm matches the upstream
# lemmy_server build environment so libpq / glibc versions agree.
FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

# System deps:
#   * postgresql-15: bundled DB, runs as the `postgres` user.
#   * nginx: front-door router (routes /_oidc, /api/v3, /pictrs,
#            /sso-bounce, /).
#   * python3 + venv + pip: OIDC bridge (Starlette + python-jose).
#     We install the python deps via apt where possible so we don't
#     do a `pip install` in the build (matches the openhost-minio
#     comment about portable build images).  python3-jwt and
#     python3-cryptography are in bookworm.
#   * curl: readiness probes from start.sh.
#   * tini: PID 1 zombie reaper / signal forwarder.
#   * gosu: drop privileges to postgres / lemmy users.
#   * Node.js: lemmy-ui is a Node SSR app.  Bundled via the
#     lemmy-ui upstream image's /usr/local/bin/node which we copy
#     in below — saves an apt install of nodejs.
RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends \
        postgresql-15 \
        postgresql-client-15 \
        nginx \
        python3 \
        python3-starlette \
        python3-jwt \
        python3-cryptography \
        python3-uvicorn \
        curl \
        tini \
        gosu \
        ca-certificates \
        procps \
        gnupg \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/nginx/sites-enabled/default

# Node.js 20 from NodeSource — Debian Bookworm's apt repo only has
# Node 18, but lemmy-ui's bundled JS uses syntax/APIs that require
# Node 20+ (we saw the upstream lemmy-ui:1.0-alpha.18 boot crash on
# Node 18 with a parse error in dist/js/server.js).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

# lemmy_server binary (statically-linked Rust, debian-bookworm
# build).  Drop into /usr/local/bin where it'll be on PATH.
COPY --from=backend-source /usr/local/bin/lemmy_server /usr/local/bin/lemmy_server

# lemmy-ui: copy the compiled JS bundle.  We DON'T copy the
# upstream node binary — that image is Alpine (musl libc) and
# our base is Debian (glibc); a musl-linked binary fails to
# load with `libc.musl-x86_64.so.1: not found`.  Use Debian's
# nodejs apt package instead (installed above).
COPY --from=ui-source /app /opt/lemmy-ui

# Create the lemmy unprivileged user; UID 1500 to avoid clashing
# with the default `_apt`/`messagebus` etc. system users.
RUN useradd --system --uid 1500 --user-group --no-create-home --shell /usr/sbin/nologin lemmy

# Application files.
COPY nginx.conf            /etc/nginx/nginx.conf
COPY config.template.hjson /opt/openhost-lemmy/config.template.hjson
COPY oidc_bridge.py        /opt/openhost-lemmy/oidc_bridge.py
COPY bootstrap.py          /opt/openhost-lemmy/bootstrap.py
COPY sso_bounce.py         /opt/openhost-lemmy/sso_bounce.py
COPY start.sh              /opt/openhost-lemmy/start.sh

EXPOSE 8080

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/openhost-lemmy/start.sh"]
