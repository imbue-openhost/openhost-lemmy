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
PG_LOG="$PERSIST/postgres.log"
LEMMY_CONFIG="$PERSIST/config.hjson"
ADMIN_PASSWORD_FILE="$PERSIST/admin-password.txt"
PG_PASSWORD_FILE="$PERSIST/postgres-password.txt"
OIDC_CLIENT_SECRET_FILE="$PERSIST/oidc-client-secret.txt"

mkdir -p "$PERSIST"
chown -R lemmy:lemmy "$PERSIST"

# -----------------------------------------------------------------
# Postgres bootstrap
# -----------------------------------------------------------------

PG_BIN="/usr/lib/postgresql/15/bin"

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

# Idempotent: create role + DB if absent.
PG_ROLE_EXISTS="$(gosu postgres "$PG_BIN/psql" -tAc "SELECT 1 FROM pg_roles WHERE rolname='lemmy'" || true)"
if [[ "$PG_ROLE_EXISTS" != "1" ]]; then
    echo "[start.sh] Creating lemmy DB role"
    gosu postgres "$PG_BIN/psql" -c "CREATE ROLE lemmy LOGIN PASSWORD '$PG_PASSWORD';"
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

if [[ ! -f "$ADMIN_PASSWORD_FILE" ]]; then
    echo "[start.sh] Generating Lemmy admin password"
    head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32 > "$ADMIN_PASSWORD_FILE"
    chmod 0600 "$ADMIN_PASSWORD_FILE"
fi
ADMIN_PASSWORD="$(cat "$ADMIN_PASSWORD_FILE")"

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

# Always re-render so config-template changes after upgrades take
# effect.  Lemmy reads this on startup.
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

# -----------------------------------------------------------------
# Start lemmy-ui
# -----------------------------------------------------------------

echo "[start.sh] Starting lemmy-ui on 127.0.0.1:1234"
LEMMY_UI_LEMMY_INTERNAL_HOST="127.0.0.1:8536" \
LEMMY_UI_LEMMY_EXTERNAL_HOST="$APP_HOST" \
LEMMY_UI_HTTPS=true \
LEMMY_UI_HOST="127.0.0.1:1234" \
LEMMY_UI_DEBUG=false \
NODE_ENV=production \
gosu lemmy /usr/local/bin/node /opt/lemmy-ui/dist/js/server.js &
UI_PID=$!

# -----------------------------------------------------------------
# Start OIDC bridge + SSO bouncer
# -----------------------------------------------------------------

OIDC_PUBLIC_BASE="https://$APP_HOST"
export OIDC_PUBLIC_BASE
export OIDC_CLIENT_ID
export OIDC_CLIENT_SECRET
export OIDC_DATA_DIR="$PERSIST/oidc"
mkdir -p "$OIDC_DATA_DIR"
chown -R lemmy:lemmy "$OIDC_DATA_DIR"

echo "[start.sh] Starting OIDC bridge on 127.0.0.1:7000"
cd /opt/openhost-lemmy
gosu lemmy uvicorn --host 127.0.0.1 --port 7000 --log-level warning oidc_bridge:app &
BRIDGE_PID=$!

echo "[start.sh] Starting SSO bouncer on 127.0.0.1:7100"
LEMMY_OAUTH_PROVIDER_ID=1 \
gosu lemmy uvicorn --host 127.0.0.1 --port 7100 --log-level warning sso_bounce:app &
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
# the provider is already registered (subsequent boots), it's a
# fast no-op.
(
    LEMMY_HOSTNAME="$APP_HOST" \
    LEMMY_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
    OIDC_CLIENT_ID="$OIDC_CLIENT_ID" \
    OIDC_CLIENT_SECRET="$OIDC_CLIENT_SECRET" \
    OIDC_PUBLIC_BASE="$OIDC_PUBLIC_BASE" \
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
