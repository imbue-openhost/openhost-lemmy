# openhost-lemmy

[Lemmy](https://join-lemmy.org/) (federated link-aggregator, fediverse Reddit) packaged for OpenHost, with an in-container OIDC bridge so the zone owner is auto-logged-in via OpenHost SSO without ever seeing Lemmy's native login page.

Deploy this on your zone and you get:

- A federated Lemmy instance at `https://lemmy.<your-zone>/`.
- The OpenHost zone owner is auto-signed-in as the Lemmy admin.
- Federated subscribe / browse / post / vote with any other Lemmy or fediverse instance (Mastodon users can subscribe to communities and reply to posts).

## Architecture

Single container running:

| Service | Port | Purpose |
|---|---|---|
| nginx | 8080 (public) | request router |
| lemmy_server | 8536 (loopback) | Rust ActivityPub backend |
| lemmy-ui | 1234 (loopback) | Node SSR frontend |
| Postgres 15 | 5432 (loopback) | Lemmy's metadata DB |
| oidc_bridge | 7000 (loopback) | OIDC provider for SSO |
| sso_bounce | 7100 (loopback) | OAuth start page (primes localStorage + 302 to /authorize) |

Supervision: bash + `wait -n` (same pattern as `openhost-sftp` / `openhost-syncthing` / `openhost-joplin`). Postgres bin from Debian Bookworm's apt repo; lemmy_server and lemmy-ui binaries copied from the official `dessalines/lemmy` and `dessalines/lemmy-ui` upstream images via Docker multi-stage build.

## How auth works

Lemmy's frontend (lemmy-ui, version 0.19.6+) supports OAuth/OIDC providers natively; admins register one via `POST /api/v3/oauth_provider`. Once registered, the provider shows up as a `Sign in with <provider>` button on Lemmy's `/login` page.

But we don't want the owner to see the login page at all, ever. So we add a small bouncer:

1. **OpenHost router** stamps `X-OpenHost-Is-Owner: true` on every owner request after JWT-verifying the `zone_auth` cookie.
2. **nginx** detects the combination `X-OpenHost-Is-Owner: true` + no Lemmy `jwt` cookie + `Accept: text/html` and rewrites the request to `/sso-bounce?prev=<original-path>`.
3. **`sso_bounce.py`** serves a tiny HTML page with inline JS that mimics what lemmy-ui's `Sign in with OpenHost` button would do: writes `oauth_state` to `localStorage` (state, oauth_provider_id, redirect_uri, prev, expires_at) and `window.location.assign(...)` to the OIDC `/authorize` URL.
4. **`oidc_bridge.py`** sees `X-OpenHost-Is-Owner: true` on `/authorize`, generates an authorization code, redirects back to `https://lemmy.<zone>/oauth/callback?code=...&state=...`.
5. **lemmy-ui's `OAuthCallback` component** reads `localStorage.oauth_state`, verifies the state matches, calls `POST /api/v3/oauth/authenticate` with the code + redirect_uri.
6. **Lemmy backend** exchanges the code with the OIDC bridge for an ID token, verifies the JWKS signature, reads `sub` + `email` claims, creates a local user (first time) or signs them in. Returns a JWT that lemmy-ui stores in localStorage AND the `jwt` cookie.
7. **Subsequent owner requests** carry the `jwt` cookie, so nginx's bouncer condition fails and traffic flows directly to lemmy-ui — no further bouncing.

Federation traffic (anonymous ActivityPub requests from remote instances) never carries `X-OpenHost-Is-Owner` so the bouncer never fires; nginx forwards them straight to Lemmy.

## Quick start

1. Deploy the app from the OpenHost dashboard.
2. Open `https://lemmy.<your-zone>/`. You'll see a brief "Signing in to Lemmy via OpenHost SSO…" splash, then land directly on Lemmy's home feed signed in as the admin user `owner`.
3. Click `Communities` to browse local + federated communities. Use `Communities → Subscribe` to follow any remote Lemmy / fediverse community by URL (`!asklemmy@lemmy.world`, etc.).

## Configuration

| Env var | Purpose | Default |
|---|---|---|
| `OPENHOST_APP_DATA_DIR` | Persistent data dir; injected by compute_space. | `/data/app_data/lemmy` |
| `OPENHOST_ZONE_DOMAIN` | Zone domain; injected. Used for `hostname` in `config.hjson` and OIDC `iss`. | `localhost` |
| `LEMMY_CONFIG_LOCATION` | Lemmy backend config path. | `$OPENHOST_APP_DATA_DIR/config.hjson` |

### Persistent files (under `$OPENHOST_APP_DATA_DIR/`)

```
postgres/                 — Postgres 15 data dir
postgres-password.txt     — auto-generated DB role password (mode 0600)
admin-password.txt        — auto-generated Lemmy admin password (mode 0600)
oidc-client-secret.txt    — auto-generated OIDC client secret (mode 0600)
config.hjson              — rendered Lemmy config (re-rendered every boot)
oidc/signing-key.pem      — OIDC bridge's RSA private key (persists so
                            already-issued ID tokens stay verifiable)
```

The admin password is the fallback if SSO ever breaks: log in directly at `https://lemmy.<zone>/login` with username `owner` and the password from `admin-password.txt`. To rotate, `rm` the file and restart the container — start.sh regenerates and re-pushes the new password to Lemmy's DB on next boot.

## Federation

Lemmy federates over ActivityPub. Other instances need to reach:

- `/.well-known/webfinger` — discovery
- `/.well-known/nodeinfo`, `/nodeinfo/2.0` — instance metadata
- `/inbox`, `/u/<user>/inbox`, `/c/<community>/inbox` — federated activities
- `/u/<user>`, `/c/<community>`, `/post/<id>`, `/comment/<id>` — actor + object profiles
- `/api/v3/*` (read-only endpoints) — federation peers occasionally fetch

All of these are listed in the OpenHost manifest's `routing.public_paths` so the OpenHost router doesn't 302 them to `/login` when accessed without a `zone_auth` cookie.

## Limitations

- **No pict-rs.** Image hosting (avatars, post thumbnails, federated remote media) is not bundled. Lemmy works without it (image features just become no-ops); add a `[[ports]]`-published pict-rs alongside if you want it.
- **Single owner.** This deployment is single-tenant by design. The OIDC bridge always claims `sub: owner@<zone>`, so every SSO sign-in lands as the same user. Federated remote users (signing up from other instances and following your communities) are handled normally; this only constrains who-can-be-an-admin-on-this-instance.
- **No outbound email.** Account confirmations and password-reset are disabled (you can't lose your password — it's in the credentials file).
- **PKCE supported** on the OIDC flow (per Lemmy 0.19.10+'s requirement) but the `state` validation is left to lemmy-ui's localStorage check. If lemmy-ui's `oauth_state` schema changes, the bouncer's inline JS would need updating to match.
- **Bundled Postgres**, not an external one. Postgres 15 from Debian Bookworm's apt repo runs in the same container; data lives under `$OPENHOST_APP_DATA_DIR/postgres/`. Backups via OpenHost's `openhost-backup` app capture this directory verbatim.

## How this is built

- **Base**: `debian:bookworm-slim`. Matches the upstream `dessalines/lemmy` build environment so libpq and glibc agree.
- **lemmy_server binary**: copied from `dessalines/lemmy:0.19.13` via `COPY --from=...`.
- **lemmy-ui**: copied from `dessalines/lemmy-ui:0.19.13` (includes the bundled Node binary).
- **Postgres**: `postgresql-15` from apt.
- **Python services** (oidc_bridge, sso_bounce, bootstrap): `starlette` + `python3-jwt` + `python3-cryptography` + `uvicorn`, all from apt — no `pip install` step in the build.
