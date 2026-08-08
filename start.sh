#!/bin/bash
# Boot Lemmy + lemmy-ui + Postgres + OIDC bridge + SSO bouncer +
# nginx for OpenHost.
#
# Topology overview:
#
#   browser → OpenHost router (subdomain lemmy.<zone>; verifies
#                              owner zone_auth, stamps
#                              X-OpenHost-Is-Owner)
#          → container :8080  (nginx)
#                ├─ /_oidc/*  → oidc_bridge.py on :7000
#                ├─ /sso-bounce → sso_bounce.py on :7100
#                ├─ /api/*    → lemmy_server on :8536
#                ├─ /pictrs/* → lemmy_server on :8536
#                ├─ /(u|c|post|comment)/ → lemmy_server  (federation)
#                ├─ /.well-known/, /nodeinfo/, /inbox, /feeds/ → lemmy_server
#                └─ /         → bouncer if owner+no-jwt+html, else
#                              lemmy-ui (Node SSR) on :1234.
#
# First-boot bootstrap:
#   * Generate strong Postgres + admin passwords.
#   * Render config.template.hjson into the Lemmy config file.
#   * Initialise Postgres data dir, create lemmy DB + user.
#   * Wait for lemmy_server to be reachable.
#   * Register the OIDC provider via the Lemmy admin API.
#
# Subsequent boots load the persisted credentials and skip all of
# the above generation steps.

set -euo pipefail

PERSIST="${OPENHOST_APP_DATA_DIR:-/data/app_data/lemmy}"
ZONE_DOMAIN="${OPENHOST_ZONE_DOMAIN:-localhost}"
APP_NAME="${OPENHOST_APP_NAME:-lemmy}"
APP_HOST="${APP_NAME}.${ZONE_DOMAIN}"

PG_DATA="$PERSIST/postgres"
PG_LOG_DIR="$PERSIST/log"
PG_LOG="$PG_LOG_DIR/postgres.log"
# Lemmy's rendered config carries the DB password AND the admin
# password in cleartext, so it must NOT live under $PERSIST (which
# file-browser's access_all_data mounts can read).  We render it to
# a container-local, non-bind-mounted path under /run instead.  The
# config is re-rendered from the template on every boot, so nothing
# is lost by not persisting it.  Older deployments wrote it to
# $PERSIST/config.hjson — scrub that legacy copy.
LEMMY_RUNTIME_DIR="/run/lemmy"
LEMMY_CONFIG="$LEMMY_RUNTIME_DIR/config.hjson"
rm -f "$PERSIST/config.hjson" 2>/dev/null || true
PG_PASSWORD_FILE="$PERSIST/postgres-password.txt"
OIDC_CLIENT_SECRET_FILE="$PERSIST/oidc-client-secret.txt"
# Legacy artifact from earlier builds: the Lemmy admin (web-login)
# password used to be persisted here in plaintext, which the
# file-browser app (access_all_data=true) could read — a real
# credential leak because it's a usable /login password.  We no
# longer persist it (see below); scrub any copy left by an older
# deployment.
LEGACY_ADMIN_PASSWORD_FILE="$PERSIST/admin-password.txt"
rm -f "$LEGACY_ADMIN_PASSWORD_FILE" 2>/dev/null || true

# Lay out persistent dirs with correct ownership.  Postgres
# specifically needs its data dir + log dir owned by the postgres
# user; the rest can be owned by lemmy.
mkdir -p "$PERSIST" "$PG_LOG_DIR"
chown postgres:postgres "$PG_LOG_DIR"
chmod 0750 "$PG_LOG_DIR"

# -----------------------------------------------------------------
# Postgres bootstrap
# -----------------------------------------------------------------

PG_BIN="/usr/lib/postgresql/16/bin"

if [[ ! -f "$PG_PASSWORD_FILE" ]]; then
    echo "[start.sh] Generating new Postgres password"
    head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32 > "$PG_PASSWORD_FILE"
    chmod 0600 "$PG_PASSWORD_FILE"
fi
PG_PASSWORD="$(cat "$PG_PASSWORD_FILE")"

if [[ ! -d "$PG_DATA/base" ]]; then
    echo "[start.sh] First boot: initialising Postgres data dir at $PG_DATA"
    mkdir -p "$PG_DATA"
    # Postgres refuses to operate on a dir owned by anyone other
    # than the user running the daemon.
    chown postgres:postgres "$PG_DATA"
    chmod 0700 "$PG_DATA"
    gosu postgres "$PG_BIN/initdb" -D "$PG_DATA" --auth=trust --username=postgres --encoding=UTF8 --locale=C 2>&1 | tail -10
fi

# Pin Postgres to localhost only.  Rootless podman gives the
# container its own network namespace anyway, but defence in
# depth: never let the DB even attempt to listen externally.
sed -i "s/^#\?listen_addresses.*/listen_addresses = '127.0.0.1'/" "$PG_DATA/postgresql.conf"
sed -i "s/^#\?port .*/port = 5432/"                                 "$PG_DATA/postgresql.conf"

echo "[start.sh] Starting Postgres on 127.0.0.1:5432"
gosu postgres "$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_LOG" -w start

# Wait until Postgres is accepting connections.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if gosu postgres "$PG_BIN/pg_isready" -h 127.0.0.1 -p 5432 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Idempotent: create role + DB if absent.  Lemmy 1.0-alpha
# migrations DROP/recreate system triggers (RI_ConstraintTrigger_*),
# which requires SUPERUSER.  Fine for a single-tenant local DB
# where the lemmy app is the only thing using Postgres.
PG_ROLE_EXISTS="$(gosu postgres "$PG_BIN/psql" -tAc "SELECT 1 FROM pg_roles WHERE rolname='lemmy'" || true)"
if [[ "$PG_ROLE_EXISTS" != "1" ]]; then
    echo "[start.sh] Creating lemmy DB role"
    gosu postgres "$PG_BIN/psql" -c "CREATE ROLE lemmy LOGIN SUPERUSER PASSWORD '$PG_PASSWORD';"
else
    gosu postgres "$PG_BIN/psql" -c "ALTER ROLE lemmy WITH SUPERUSER;" >/dev/null
fi
PG_DB_EXISTS="$(gosu postgres "$PG_BIN/psql" -tAc "SELECT 1 FROM pg_database WHERE datname='lemmy'" || true)"
if [[ "$PG_DB_EXISTS" != "1" ]]; then
    echo "[start.sh] Creating lemmy DB"
    gosu postgres "$PG_BIN/psql" -c "CREATE DATABASE lemmy OWNER lemmy;"
fi

# Always sync the password in case it's been rotated (delete the
# password file + restart to force).
gosu postgres "$PG_BIN/psql" -c "ALTER ROLE lemmy WITH PASSWORD '$PG_PASSWORD';" >/dev/null

# -----------------------------------------------------------------
# Admin password + OIDC client secret
# -----------------------------------------------------------------

# Lemmy admin (web-login) password for the `owner` provisioning
# account.  This is a usable /login credential, so we NEVER write
# it to disk (file-browser could read it).  Instead we mint a fresh
# random one in-memory on every boot and have bootstrap.py re-stamp
# it into Lemmy's `local_user.password_encrypted` (bcrypt) before
# it logs in.  Effect: the owner password silently rotates every
# container start and nothing usable ever lands in $PERSIST.
#
# The owner account is a break-glass admin anyway — normal use is
# the SSO-minted `openhost` admin.  If an operator needs to log in
# as `owner` directly they can read this value from the container's
# start.sh environment (podman exec) at runtime, or just rely on
# SSO.
echo "[start.sh] Minting ephemeral Lemmy admin password (in-memory only)"
ADMIN_PASSWORD="$(head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 40)"

if [[ ! -f "$OIDC_CLIENT_SECRET_FILE" ]]; then
    echo "[start.sh] Generating OIDC client secret"
    head -c 48 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 48 > "$OIDC_CLIENT_SECRET_FILE"
    chmod 0600 "$OIDC_CLIENT_SECRET_FILE"
fi
OIDC_CLIENT_SECRET="$(cat "$OIDC_CLIENT_SECRET_FILE")"
OIDC_CLIENT_ID="openhost-lemmy"

# -----------------------------------------------------------------
# Render Lemmy config
# -----------------------------------------------------------------

# Lemmy + lemmy-ui run as the lemmy user.  Make sure the rest of
# $PERSIST (excluding postgres dirs) is readable by them.  We do
# this only on dirs lemmy will read/write so we don't fight the
# postgres user's exclusive ownership of $PG_DATA / $PG_LOG_DIR.
chown lemmy:lemmy "$PERSIST"
for d in "$PERSIST"/oidc; do
    [[ -e "$d" ]] && chown -R lemmy:lemmy "$d"
done

# Always re-render so config-template changes after upgrades take
# effect.  Lemmy reads this on startup.  Rendered to /run (tmpfs-ish
# container-local storage), never to $PERSIST, so the embedded DB +
# admin passwords are never exposed to file-browser.
mkdir -p "$LEMMY_RUNTIME_DIR"
chmod 0710 "$LEMMY_RUNTIME_DIR"
chown lemmy:lemmy "$LEMMY_RUNTIME_DIR"
sed \
    -e "s|__POSTGRES_PASSWORD__|$PG_PASSWORD|g" \
    -e "s|__HOSTNAME__|$APP_HOST|g" \
    -e "s|__ADMIN_PASSWORD__|$ADMIN_PASSWORD|g" \
    /opt/openhost-lemmy/config.template.hjson > "$LEMMY_CONFIG"
chown lemmy:lemmy "$LEMMY_CONFIG"
chmod 0600 "$LEMMY_CONFIG"

# -----------------------------------------------------------------
# Start lemmy_server
# -----------------------------------------------------------------

echo "[start.sh] Starting lemmy_server on 127.0.0.1:8536"
LEMMY_DATABASE_URL="postgres://lemmy:$PG_PASSWORD@localhost:5432/lemmy" \
LEMMY_CONFIG_LOCATION="$LEMMY_CONFIG" \
RUST_LOG=warn \
gosu lemmy /usr/local/bin/lemmy_server &
LEMMY_PID=$!

# Wait for lemmy_server to finish migrations + bind its port
# BEFORE we start anything else.  First-boot migrations on a fresh
# Postgres can take 30+s; killing postgres or lemmy mid-migration
# leaves a half-applied schema that's hard to recover from.  Poll
# /api/v3/site (anonymous, lightweight) until ready.
echo "[start.sh] Waiting for lemmy_server migrations + readiness..."
LEMMY_READY=0
for i in $(seq 1 180); do
    if python3 -c "
import sys, urllib.request
try:
    r = urllib.request.urlopen('http://127.0.0.1:8536/api/v3/site', timeout=3)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        LEMMY_READY=1
        echo "[start.sh] lemmy_server ready after ${i}s"
        break
    fi
    if ! kill -0 "$LEMMY_PID" 2>/dev/null; then
        wait "$LEMMY_PID" || true
        echo "[start.sh] lemmy_server exited before becoming ready"
        gosu postgres "$PG_BIN/pg_ctl" -D "$PG_DATA" stop -m fast || true
        exit 1
    fi
    sleep 1
done
if [[ "$LEMMY_READY" != "1" ]]; then
    echo "[start.sh] lemmy_server did not become ready within 180s; aborting"
    kill -TERM "$LEMMY_PID" 2>/dev/null || true
    gosu postgres "$PG_BIN/pg_ctl" -D "$PG_DATA" stop -m fast || true
    exit 1
fi

# -----------------------------------------------------------------
# Start lemmy-ui
# -----------------------------------------------------------------

echo "[start.sh] Starting lemmy-ui on 127.0.0.1:1234"
# lemmy-ui's server.js opens dist/js/embedded.js relative to CWD,
# so we cd into /opt/lemmy-ui first.
#
# Env vars: lemmy-ui v1.x uses LEMMY_UI_BACKEND_INTERNAL (loopback
# URL the SSR uses to talk to lemmy_server) and LEMMY_UI_BACKEND
# (the public URL the SPA emits in browser-side code).  Earlier
# versions used LEMMY_UI_LEMMY_INTERNAL_HOST / LEMMY_UI_LEMMY_EXTERNAL_HOST
# which the v1 server.js ignores entirely — those names are gone
# from src/shared/utils/env.ts and silently fall back to the
# baked-in testHost = "localhost:8536".
#
# We set BOTH env-var names so this start.sh keeps working if a
# future image happens to be a backport to 0.19.x; the
# v1.0-alpha+ image reads only the BACKEND_* pair.
#
# Crucially we INCLUDE the http:// scheme in
# LEMMY_UI_BACKEND_INTERNAL.  Without it, lemmy-ui's getBaseUrl
# applies LEMMY_UI_HTTPS=true and tries to TLS-handshake against
# the loopback address — but lemmy_server speaks plain HTTP, so
# every SSR backend call dies on the handshake and actix logs
# "invalid Header provided" while the SPA shows a 500 error
# page (which is what an /oauth/callback render hits because it
# can't fail-soft like the other routes).  See
# https://github.com/LemmyNet/lemmy-ui/blob/1.0.0-alpha.18/src/shared/utils/env.ts#L28
# for the protocol-prefix logic.
# Both the v1.x env-var pair (LEMMY_UI_BACKEND_INTERNAL /
# LEMMY_UI_BACKEND, canonical for v1.0.0-alpha+) and the legacy
# 0.19.x env-var pair (LEMMY_UI_LEMMY_INTERNAL_HOST /
# LEMMY_UI_LEMMY_EXTERNAL_HOST) are listed below — the active
# image only consumes the v1.x pair, the legacy names are kept
# in case a future image bump regresses to the older naming.
# Inline comments interspersed with `\` continuations would
# silently truncate the env-var chain in bash, so all comments
# stay outside the prefix block.
(
    cd /opt/lemmy-ui
    LEMMY_UI_BACKEND_INTERNAL="http://127.0.0.1:8536" \
    LEMMY_UI_BACKEND="https://$APP_HOST" \
    LEMMY_UI_LEMMY_INTERNAL_HOST="127.0.0.1:8536" \
    LEMMY_UI_LEMMY_EXTERNAL_HOST="$APP_HOST" \
    LEMMY_UI_HTTPS=true \
    LEMMY_UI_HOST="127.0.0.1:1234" \
    LEMMY_UI_DEBUG=false \
    NODE_ENV=production \
    exec gosu lemmy /usr/bin/node /opt/lemmy-ui/dist/js/server.js
) &
UI_PID=$!

# -----------------------------------------------------------------
# Start OIDC bridge + SSO bouncer
# -----------------------------------------------------------------

OIDC_PUBLIC_BASE="https://$APP_HOST"
# OIDC_LOOPBACK_BASE is the URL the Lemmy backend uses when it
# server-to-server-calls the OIDC bridge (token exchange,
# userinfo).  Routing those server hops via the public hostname
# would hit Hetzner / EC2 / GCP NAT-loopback restrictions
# ("connect: connection refused" when a host tries to reach its
# own public IP), so we keep them on loopback.  See bootstrap.py
# `_provider_payload` for the full reasoning.
OIDC_LOOPBACK_BASE="http://127.0.0.1:7000"
# SSO_USERNAME is the Lemmy username the synthetic OpenHost-SSO
# user takes on first sign-in.  Both bootstrap.py (admin
# promotion) and sso_bounce.py (localStorage prefill) read this
# env var — change it in one place and both pick it up.
SSO_USERNAME="${SSO_USERNAME:-openhost}"
export OIDC_PUBLIC_BASE
export OIDC_LOOPBACK_BASE
export OIDC_CLIENT_ID
export OIDC_CLIENT_SECRET
export OIDC_DATA_DIR="$PERSIST/oidc"
export SSO_USERNAME
mkdir -p "$OIDC_DATA_DIR"
chown -R lemmy:lemmy "$OIDC_DATA_DIR"

echo "[start.sh] Starting OIDC bridge on 127.0.0.1:7000"
cd /opt/openhost-lemmy
# python3-uvicorn (Debian's apt package) ships the library but
# not a /usr/bin/uvicorn script — invoke via `python3 -m uvicorn`.
gosu lemmy python3 -m uvicorn --host 127.0.0.1 --port 7000 --log-level warning --app-dir /opt/openhost-lemmy oidc_bridge:app &
BRIDGE_PID=$!

echo "[start.sh] Starting SSO bouncer on 127.0.0.1:7100"
LEMMY_OAUTH_PROVIDER_ID=1 \
SSO_USERNAME="$SSO_USERNAME" \
gosu lemmy python3 -m uvicorn --host 127.0.0.1 --port 7100 --log-level warning --app-dir /opt/openhost-lemmy sso_bounce:app &
BOUNCE_PID=$!

# -----------------------------------------------------------------
# Start nginx
# -----------------------------------------------------------------

echo "[start.sh] Starting nginx on 0.0.0.0:8080"
nginx -g 'daemon off;' &
NGINX_PID=$!

# -----------------------------------------------------------------
# Bootstrap: register the OIDC provider with Lemmy
# -----------------------------------------------------------------

# Run in the background so it doesn't block container startup.  If
# the provider is already registered with the right endpoints
# (subsequent boots), it's a fast no-op.  bootstrap.py also takes
# care of:
#   * keeping the registration_mode set to ``open`` (so the OIDC
#     user-creation path doesn't trip on the application-question gate)
#   * promoting the SSO_USERNAME user to admin once it exists (it's
#     created lazily on the first SSO sign-in, so this is a no-op
#     until then).
(
    LEMMY_HOSTNAME="$APP_HOST" \
    LEMMY_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    LEMMY_ADMIN_USERNAME="owner" \
    LEMMY_DATABASE_URL="postgres://lemmy:$PG_PASSWORD@localhost:5432/lemmy" \
    OIDC_CLIENT_ID="$OIDC_CLIENT_ID" \
    OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
    OIDC_PUBLIC_BASE="$OIDC_PUBLIC_BASE" \
    OIDC_LOOPBACK_BASE="$OIDC_LOOPBACK_BASE" \
    SSO_USERNAME="$SSO_USERNAME" \
    python3 /opt/openhost-lemmy/bootstrap.py 2>&1 \
    | sed 's/^/[bootstrap] /'
) &

# -----------------------------------------------------------------
# Supervision
# -----------------------------------------------------------------

trap 'kill -TERM "$NGINX_PID" "$LEMMY_PID" "$UI_PID" "$BRIDGE_PID" "$BOUNCE_PID" 2>/dev/null; gosu postgres "'"$PG_BIN"'/pg_ctl" -D "'"$PG_DATA"'" stop -m fast 2>/dev/null; wait' TERM INT

set +e
wait -n "$NGINX_PID" "$LEMMY_PID" "$UI_PID" "$BRIDGE_PID" "$BOUNCE_PID"
EXIT_CODE=$?
set -e

echo "[start.sh] Child exited (code=$EXIT_CODE); shutting down"
kill -TERM "$NGINX_PID" "$LEMMY_PID" "$UI_PID" "$BRIDGE_PID" "$BOUNCE_PID" 2>/dev/null || true
gosu postgres "$PG_BIN/pg_ctl" -D "$PG_DATA" stop -m fast 2>/dev/null || true
wait || true
exit "$EXIT_CODE"
