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

Two Lemmy users share this single-tenant deployment:

- **`owner`** — the bootstrap admin created by Lemmy's setup flow.  Has a password (in `admin-password.txt`) for break-glass access, but normally untouched.  Owns the OAuth provider registration + the registration-mode toggle that the SSO flow depends on.
- **`openhost`** — the dedicated OpenHost-SSO user, created lazily the first time the zone owner signs in via SSO.  Promoted to admin by `bootstrap.py` once it appears.  This is the user the owner ends up signed-in as for normal day-to-day use.

The two are separate because Lemmy's OAuth flow refuses to claim a pre-existing local user as an OIDC identity — so the SSO has to mint its own user, and the bouncer pre-fills `username = "openhost"` to avoid colliding with the admin.

The end-to-end flow:

1. **OpenHost router** stamps `X-OpenHost-Is-Owner: true` on every owner request after JWT-verifying the `zone_auth` cookie.
2. **nginx** detects the combination `X-OpenHost-Is-Owner: true` + no Lemmy `jwt` cookie + `Accept: text/html` and rewrites the request to `/sso-bounce?prev=<original-path>`.
3. **`sso_bounce.py`** serves a tiny HTML page with inline JS that mimics what lemmy-ui's `Sign in with OpenHost` button would do: writes `oauth_state` to `localStorage` (state, oauth_provider_id, redirect_uri, prev, expires_at, **username=openhost**) and `window.location.assign(...)` to the OIDC `/authorize` URL.
4. **`oidc_bridge.py`** sees `X-OpenHost-Is-Owner: true` on `/authorize`, generates an authorization code, redirects back to `https://lemmy.<zone>/oauth/callback?code=...&state=...`.
5. **lemmy-ui's `OAuthCallback` component** reads `localStorage.oauth_state`, verifies the state matches, calls `POST /api/v4/oauth/authenticate` with the code + redirect_uri + username.
6. **Lemmy backend** exchanges the code with the OIDC bridge **via loopback** (see "Loopback OIDC plumbing" below for why), verifies the JWKS signature, reads `sub` + `email` claims, creates the local `openhost` user (first time) or signs them in.  Returns a JWT that lemmy-ui stores in localStorage AND the `jwt` cookie.
7. **`bootstrap.py`'s admin-watcher** (running in the background since container start) sees the `openhost` user appear and promotes them to admin via `POST /api/v4/admin/add`.  This makes the SSO sign-in the *admin* user; `bootstrap.py` exits once the promotion succeeds.
8. **Subsequent owner requests** carry the Lemmy `jwt` cookie, so nginx's bouncer condition fails and traffic flows directly to lemmy-ui — no further bouncing.

Federation traffic (anonymous ActivityPub requests from remote instances) never carries `X-OpenHost-Is-Owner` so the bouncer never fires; nginx forwards them straight to Lemmy.

### Loopback OIDC plumbing

The OAuth provider is registered with a deliberate split of public and loopback endpoints:

| Endpoint | URL | Why |
|---|---|---|
| `authorization_endpoint` | `https://lemmy.<zone>/_oidc/authorize` | The browser navigates here directly; must be public. |
| `token_endpoint` | `http://127.0.0.1:7000/_oidc/token` | Lemmy backend calls this server-to-server. |
| `userinfo_endpoint` | `http://127.0.0.1:7000/_oidc/userinfo` | Lemmy backend calls this server-to-server. |
| `issuer` | `https://lemmy.<zone>/_oidc` | Validated against the `iss` claim that the bridge mints; public form keeps issued tokens externally-verifiable. |

The reason `token_endpoint` and `userinfo_endpoint` use loopback (rather than the public URL): on most cloud providers the host can't connect to its own public IP — NAT-loopback / hairpinning is disabled by default.  Routing the server-to-server hops via `127.0.0.1` sidesteps the entire NAT layer.  The OIDC bridge runs in the same container so loopback is always reachable.

`bootstrap.py` reconciles this configuration on every container start: existing deployments that were registered with public-URL endpoints get upgraded in place with no operator intervention.

### Registration mode

Lemmy's OAuth user-creation path goes through the same code as a self-registration via the `/signup` form, including the `registration_mode = require_application` gate.  On a single-tenant openhost-lemmy that gate has nowhere to obtain an application-question answer from (the bouncer's `oauth_state` carries `answer: undefined`), so it would reject the SSO sign-in with `registration_application_answer_required`.

`bootstrap.py` fixes this by setting `registration_mode = open` once on first boot.  Federated remote users on other instances are unaffected by this setting; only signups *to this instance* are influenced, and on a single-tenant deploy the only real signup path is the SSO bounce.

## Quick start

1. Deploy the app from the OpenHost dashboard.
2. Open `https://lemmy.<your-zone>/`. You'll see a brief "Signing in to Lemmy via OpenHost SSO…" splash, then land directly on Lemmy's home feed signed in as the user `openhost`.  The first sign-in creates that user as a non-admin; `bootstrap.py`'s background watcher promotes them to admin within ~30 seconds (refresh the page to pick up the promoted role).
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
- **Single owner.** This deployment is single-tenant by design. The OIDC bridge always claims `sub: owner@<zone>`, so every SSO sign-in lands as the same `openhost` user. Federated remote users (signing up from other instances and following your communities) are handled normally; this only constrains who-can-be-an-admin-on-this-instance.
- **No outbound email.** Account confirmations and password-reset are disabled (you can't lose your password — it's in the credentials file).
- **PKCE supported** on the OIDC flow (per Lemmy 0.19.10+'s requirement) but the `state` validation is left to lemmy-ui's localStorage check. If lemmy-ui's `oauth_state` schema changes, the bouncer's inline JS would need updating to match.
- **Bundled Postgres**, not an external one. Postgres 15 from Debian Bookworm's apt repo runs in the same container; data lives under `$OPENHOST_APP_DATA_DIR/postgres/`. Backups via OpenHost's `openhost-backup` app capture this directory verbatim.

## How this is built

- **Base**: `debian:bookworm-slim`. Matches the upstream `dessalines/lemmy` build environment so libpq and glibc agree.
- **lemmy_server binary**: copied from `dessalines/lemmy:0.19.13` via `COPY --from=...`.
- **lemmy-ui**: copied from `dessalines/lemmy-ui:0.19.13` (includes the bundled Node binary).
- **Postgres**: `postgresql-15` from apt.
- **Python services** (oidc_bridge, sso_bounce, bootstrap): `starlette` + `python3-jwt` + `python3-cryptography` + `uvicorn`, all from apt — no `pip install` step in the build.
