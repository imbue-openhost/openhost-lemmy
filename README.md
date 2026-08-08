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
| Postgres 16 | 5432 (loopback) | Lemmy's metadata DB |
| oidc_bridge | 7000 (loopback) | OIDC provider for SSO |
| sso_bounce | 7100 (loopback) | OAuth start page (primes localStorage + 302 to /authorize) |

Supervision: bash + `wait -n` (same pattern as `openhost-sftp` / `openhost-syncthing` / `openhost-joplin`). Postgres bin from Debian Bookworm's apt repo; lemmy_server and lemmy-ui binaries copied from the official `dessalines/lemmy` and `dessalines/lemmy-ui` upstream images via Docker multi-stage build.

## How auth works

Two Lemmy users share this single-tenant deployment:

- **`owner`** — the bootstrap admin created by Lemmy's setup flow.  Its web-login password is minted fresh in-memory on every container boot and re-stamped into Lemmy's `local_user.password_encrypted` (bcrypt) by `bootstrap.py` — it is **never written to disk**, so the file-browser app can't read it.  Normally untouched; it owns the OAuth-provider registration + the registration-mode toggle the SSO flow depends on.  If you need break-glass access as `owner`, read the live value from the container's `start.sh` environment (`podman exec … printenv`) — or just use SSO.
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
postgres/                 — Postgres 16 data dir
postgres-password.txt     — auto-generated DB role password (mode 0600)
oidc-client-secret.txt    — auto-generated OIDC client secret (mode 0600)
oidc/signing-key.pem      — OIDC bridge's RSA private key (persists so
                            already-issued ID tokens stay verifiable)
```

Two things deliberately do **not** live under `$OPENHOST_APP_DATA_DIR`:

- **The Lemmy admin (web-login) password.** It's minted in-memory each
  boot and re-stamped into the DB by `bootstrap.py`; nothing usable lands
  on disk.  Earlier builds persisted it as `admin-password.txt` — that was
  a credential leak (file-browser's `access_all_data` mount could read a
  live `/login` password).  `start.sh` scrubs any legacy copy on boot.
- **The rendered `config.hjson`** (which embeds the DB + admin passwords in
  cleartext).  It's written to a container-local `/run/lemmy/config.hjson`
  (not a bind mount) and re-rendered every boot, so it never appears under
  `app_data` either.  `start.sh` scrubs any legacy `$PERSIST/config.hjson`.

`postgres-password.txt` and `oidc-client-secret.txt` remain on disk: neither
is a user password.  Postgres binds loopback-only, so the DB password is only
useful to something already inside the container (same trust boundary as
file-browser reading it), and the OIDC client secret only lets a party that
already controls this container mint tokens for this one app.

To rotate the DB password, `rm postgres-password.txt` and restart — start.sh
regenerates it and `ALTER ROLE`s the new one. The admin password rotates on
its own every boot.

## Federation

Lemmy federates over ActivityPub. Other instances need to reach:

- `/.well-known/webfinger` — discovery
- `/.well-known/nodeinfo`, `/nodeinfo/2.0` — instance metadata
- `/inbox`, `/u/<user>/inbox`, `/c/<community>/inbox` — federated activities
- `/u/<user>`, `/c/<community>`, `/post/<id>`, `/comment/<id>` — actor + object profiles
- `/api/v3/*` (read-only endpoints) — federation peers occasionally fetch

The manifest's `routing.public_paths` is set to `"/"` (the whole app), so the OpenHost router never 302s an anonymous visitor to `/login` — whether they're a federation peer hitting the Inbox or a human browsing the web UI.

## Anonymous viewing

Lemmy is a public link-aggregator, so anonymous (non-owner) visitors can browse the whole instance read-only: the web UI, communities, user profiles, posts, and comments. This works because `routing.public_paths = ["/"]` tells the OpenHost router to let unauthenticated traffic through.

This does not weaken SSO. The OpenHost router still verifies the owner's `zone_auth` cookie on **every** request (public paths only suppress the login-redirect on auth *failure*; they never skip the owner-auth attempt), so it still stamps `X-OpenHost-Is-Owner: true` when the owner is signed in. nginx's SSO bounce keys off that header, so the owner is still auto-logged-in while anonymous visitors get the read-only view. Lemmy's own permission model still governs who can post/vote/moderate.

## Limitations

- **No pict-rs.** Image hosting (avatars, post thumbnails, federated remote media) is not bundled. Lemmy works without it (image features just become no-ops); add a `[[ports]]`-published pict-rs alongside if you want it.
- **Single owner.** This deployment is single-tenant by design. The OIDC bridge always claims `sub: owner@<zone>`, so every SSO sign-in lands as the same `openhost` user. Federated remote users (signing up from other instances and following your communities) are handled normally; this only constrains who-can-be-an-admin-on-this-instance.
- **No outbound email.** Account confirmations and password-reset are disabled. This is fine for the single-tenant owner because normal access is via OpenHost SSO (no password needed); the break-glass `owner` password is minted in-memory each boot rather than stored, so there's nothing to "reset".
- **PKCE supported** on the OIDC flow (per Lemmy 0.19.10+'s requirement) but the `state` validation is left to lemmy-ui's localStorage check. If lemmy-ui's `oauth_state` schema changes, the bouncer's inline JS would need updating to match.
- **Bundled Postgres**, not an external one. Postgres 16 (from the pgdg apt repo — Lemmy 1.0-alpha's migrations use Postgres-16-only SQL) runs in the same container; data lives under `$OPENHOST_APP_DATA_DIR/postgres/`. Backups via OpenHost's `openhost-backup` app capture this directory verbatim.

## How this is built

- **Base**: `debian:bookworm-slim`. Matches the upstream `dessalines/lemmy` build environment so libpq and glibc agree.
- **lemmy_server binary**: copied from `dessalines/lemmy:1.0.0-alpha.18` via `COPY --from=...` (OAuth/OIDC — required for SSO — landed only in the 1.0 series; 0.19.x has no `oauth_provider` API).
- **lemmy-ui**: copied from `dessalines/lemmy-ui:1.0.0-alpha.18` (JS bundle only; Node itself comes from NodeSource apt because the upstream image is musl/Alpine).
- **Postgres**: `postgresql-16` from the pgdg apt repo.
- **Python services** (oidc_bridge, sso_bounce, bootstrap): `starlette` + `python3-jwt` + `python3-cryptography` + `uvicorn`, all from apt — no `pip install` step in the build.
