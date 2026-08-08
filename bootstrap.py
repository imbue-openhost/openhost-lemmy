#!/usr/bin/env python3
"""First-boot OIDC-provider registration + SSO-readiness for openhost-lemmy.

Runs on every container start; idempotent.  Tasks (in order):

  1. Wait for Lemmy to come up.
  2. Log in as the provisioning admin (``owner``) using the password
     persisted in ``admin-password.txt`` so we have a JWT for the
     subsequent admin-only API calls.
  3. Register (or, on subsequent boots, *reconcile*) the OIDC
     ``oauth_provider`` row.  We always re-PUT the endpoints because
     the design changed mid-life: token_endpoint and userinfo_endpoint
     are now loopback URLs so Lemmy backend can reach them without
     hairpinning back through the public hostname.  See the long
     comment in ``_provider_payload`` for the why.
  4. Set ``local_site.registration_mode = open`` so the OIDC
     user-creation path can mint the synthetic ``openhost`` SSO user
     without bouncing off the new-account application gate.
  5. Watch for the ``openhost`` user appearing (lazily created on
     the first SSO sign-in) and promote them to admin.  Loops with
     a short sleep between probes; exits cleanly once the user is
     promoted or after the watch window expires.  Subsequent
     container restarts re-enter the loop and short-circuit on
     finding an already-promoted user, so this is idempotent across
     reboots and the operator can sign in for the first time at
     any point — the next bootstrap iteration will catch up.

Configuration via env:
  * LEMMY_API_URL         — http://127.0.0.1:8536/api/v4
  * LEMMY_HOSTNAME        — public hostname (e.g. lemmy.<zone>)
  * LEMMY_ADMIN_USERNAME  — provisioning admin username (default: owner)
  * LEMMY_ADMIN_PASSWORD  — provisioning admin password from config.hjson
  * OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_PUBLIC_BASE
  * OIDC_LOOPBACK_BASE    — internal URL the Lemmy backend uses for
                            server-to-server OIDC calls.  Defaults to
                            http://127.0.0.1:7000 (matches start.sh).
  * SSO_USERNAME          — Lemmy username the synthetic SSO user
                            takes.  Defaults to "openhost"; must NOT
                            collide with the provisioning admin
                            (LEMMY_ADMIN_USERNAME) or any other
                            pre-existing user.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

LEMMY_API = os.environ.get("LEMMY_API_URL", "http://127.0.0.1:8536/api/v4").rstrip("/")
LEMMY_HOSTNAME = os.environ["LEMMY_HOSTNAME"]
ADMIN_USERNAME = os.environ.get("LEMMY_ADMIN_USERNAME", "owner")
ADMIN_PASSWORD = os.environ["LEMMY_ADMIN_PASSWORD"]
# Connection string for the bundled Postgres.  Used only to re-stamp
# the owner admin's bcrypt password each boot (see
# _reset_admin_password_in_db).  Optional: if unset we skip the
# reset and assume the config.hjson setup block already created the
# owner with ADMIN_PASSWORD (true on first boot).
DATABASE_URL = os.environ.get("LEMMY_DATABASE_URL", "")
# Lemmy hashes local-user passwords with bcrypt cost 12 (the
# "$2b$12$" prefix).  We must match that cost so the hash we write
# verifies against Lemmy's password checker.
BCRYPT_COST = 12
PSQL_BIN = os.environ.get("PSQL_BIN", "/usr/lib/postgresql/16/bin/psql")
OIDC_CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
OIDC_PUBLIC_BASE = os.environ["OIDC_PUBLIC_BASE"].rstrip("/")
OIDC_LOOPBACK_BASE = os.environ.get(
    "OIDC_LOOPBACK_BASE", "http://127.0.0.1:7000"
).rstrip("/")
SSO_USERNAME = os.environ.get("SSO_USERNAME", "openhost")

PROVIDER_DISPLAY = "OpenHost"


def _request(
    method: str,
    path: str,
    body: dict | None = None,
    auth: str | None = None,
) -> tuple[int, dict]:
    url = f"{LEMMY_API}{path}"
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = f"Bearer {auth}"
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            payload = {"error": "<unparseable response body>"}
        return exc.code, payload


def _wait_for_lemmy(max_seconds: int = 180) -> None:
    """Poll /api/v4/site until Lemmy responds.  ``start.sh`` already
    waits at the loopback level before invoking us, but this is a
    cheap second line of defence in case migrations slip past the
    loopback readiness check."""
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{LEMMY_API}/site", timeout=5) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    raise SystemExit("[bootstrap] timed out waiting for Lemmy /api/v4/site")


def _reset_admin_password_in_db() -> None:
    """Re-stamp the ``owner`` admin's password to the in-memory
    ADMIN_PASSWORD by writing a fresh bcrypt hash directly into
    Postgres.

    Why this exists: the admin (web-login) password is deliberately
    NOT persisted to disk (it would be readable by the file-browser
    app).  start.sh mints a new random one in-memory every boot.  On
    the very first boot Lemmy's ``config.hjson`` setup block creates
    the ``owner`` user with that password, so login would work
    without this step — but on every SUBSEQUENT boot the setup block
    is a no-op (an admin already exists) and the DB still holds the
    PREVIOUS boot's password, so our fresh ADMIN_PASSWORD wouldn't
    match.  Re-stamping the hash here keeps the in-memory password
    and the DB in sync on every boot, at the cost of nothing on disk.

    Idempotent and safe to run on first boot too (it just overwrites
    the identical-purpose hash).  If anything about the reset fails
    (missing bcrypt, psql, or DB URL) we log and continue: on first
    boot the config-created password still works, and a hard failure
    here shouldn't take down the whole app.
    """
    if not DATABASE_URL:
        print("[bootstrap] no LEMMY_DATABASE_URL; skipping admin password reset")
        return
    try:
        import bcrypt
    except ImportError:
        print(
            "[bootstrap] WARN: python3-bcrypt not available; cannot reset "
            "admin password in DB (first-boot config password still applies)",
            file=sys.stderr,
        )
        return

    hashed = bcrypt.hashpw(
        ADMIN_PASSWORD.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_COST),
    ).decode("ascii")

    # Update only the local_user row belonging to the ``owner``
    # person.  Parameterise via psql variables so the password hash
    # (which can't contain quotes anyway, but defence in depth) and
    # username are passed safely, never string-interpolated into SQL.
    sql = (
        "UPDATE local_user SET password_encrypted = :'hash' "
        "WHERE person_id = (SELECT id FROM person "
        "WHERE name = :'uname' AND local = true);"
    )
    cmd = [
        PSQL_BIN,
        DATABASE_URL,
        "-v", "ON_ERROR_STOP=1",
        "-v", f"hash={hashed}",
        "-v", f"uname={ADMIN_USERNAME}",
        "-tAc", sql,
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(
            f"[bootstrap] WARN: admin password reset psql invocation failed: {exc}",
            file=sys.stderr,
        )
        return
    if result.returncode != 0:
        print(
            f"[bootstrap] WARN: admin password reset returned "
            f"rc={result.returncode} stderr={result.stderr.strip()!r}",
            file=sys.stderr,
        )
        return
    # psql prints the UPDATE row-count tag like "UPDATE 1".
    print(f"[bootstrap] admin password re-stamped in DB ({result.stdout.strip() or 'UPDATE'})")


def _login() -> str:
    print(f"[bootstrap] logging in as {ADMIN_USERNAME!r}")
    status, payload = _request(
        "POST",
        "/account/auth/login",
        {"username_or_email": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    if status != 200 or "jwt" not in payload:
        print(
            f"[bootstrap] FATAL: admin login returned status={status} payload={payload!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return payload["jwt"]


def _site(jwt_token: str) -> dict:
    """Fetch ``/site`` as the admin.  Carries everything we need for
    reconciliation: the OAuth-provider list (``admin_oauth_providers``),
    the local-site config (``local_site_view.local_site``), and the
    admin list (``admins``)."""
    status, payload = _request("GET", "/site", auth=jwt_token)
    if status != 200:
        print(
            f"[bootstrap] FATAL: GET /site returned status={status} payload={payload!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return payload


def _provider_payload() -> dict:
    """Construct the OAuth-provider config we want stored in Lemmy.

    Endpoint split — read this carefully if you're updating it:

      * ``authorization_endpoint`` is the URL the BROWSER navigates
        to in step 1 of the OAuth code flow.  It must be the
        public, internet-reachable URL because the visitor's
        browser hits it directly.

      * ``token_endpoint`` and ``userinfo_endpoint`` are URLs the
        LEMMY BACKEND calls server-to-server.  These run *inside the
        same container* as the OIDC bridge, so they go via loopback
        (``OIDC_LOOPBACK_BASE``).  Why not the public URL?  Because
        most cloud providers (Hetzner, EC2 SG, GCP, …) refuse to
        let a host connect back to its own public IP via NAT
        ("hairpinning"); ``connect: connection refused`` is the
        common failure mode.  Routing the server-to-server hops via
        loopback sidesteps the NAT entirely.

      * ``issuer`` is the value Lemmy validates against the ``iss``
        claim in the OIDC ID token.  It must match exactly what the
        OIDC bridge mints, which is ``${OIDC_PUBLIC_BASE}/_oidc``.
        We do NOT swap it to the loopback form: the bridge could in
        principle be reconfigured to claim a loopback iss, but
        keeping the public form makes the issued tokens
        externally-verifiable (any third party with the JWKS could
        check signatures against the same issuer).
    """
    return {
        "display_name": PROVIDER_DISPLAY,
        "issuer": f"{OIDC_PUBLIC_BASE}/_oidc",
        "authorization_endpoint": f"{OIDC_PUBLIC_BASE}/_oidc/authorize",
        "token_endpoint": f"{OIDC_LOOPBACK_BASE}/_oidc/token",
        "userinfo_endpoint": f"{OIDC_LOOPBACK_BASE}/_oidc/userinfo",
        "id_claim": "sub",
        "client_id": OIDC_CLIENT_ID,
        "client_secret": OIDC_CLIENT_SECRET,
        "scopes": "openid email profile",
        "auto_verify_email": True,
        "auto_approve_application": True,
        "account_linking_enabled": True,
        "use_pkce": True,
        "enabled": True,
    }


def _reconcile_provider(jwt_token: str, providers: list[dict]) -> None:
    """Create or update the OpenHost OAuth provider so the stored
    endpoints match the current ``OIDC_*`` env config.

    Lemmy treats provider rows as long-lived: we can't safely delete
    and recreate (it would break any users who already linked their
    OIDC account to a Lemmy user).  Instead we PUT the matching row
    in place when the configured endpoints drift from what's stored
    — this lets us roll out endpoint changes (e.g. flipping
    token_endpoint from public to loopback) without operator
    intervention.
    """
    desired = _provider_payload()
    existing = next(
        (p for p in providers if p.get("display_name") == PROVIDER_DISPLAY),
        None,
    )

    if existing is None:
        print("[bootstrap] registering OpenHost OAuth provider")
        status, payload = _request("POST", "/oauth_provider", desired, auth=jwt_token)
        if status >= 400:
            print(
                f"[bootstrap] FATAL: oauth_provider create returned "
                f"status={status} payload={payload!r}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print(f"[bootstrap] OAuth provider registered (id={payload.get('id')})")
        return

    # Compare the stored endpoints against what we'd configure
    # today.  If anything material drifted (the public hostname
    # changed, we redesigned the loopback split, etc.), patch in
    # place.  We deliberately do NOT compare client_secret here —
    # PUTting a new secret would orphan any existing OIDC sessions,
    # and the operator can rotate the secret out-of-band by
    # deleting the persisted file and restarting the container.
    drift_keys = (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "id_claim",
        "scopes",
        "auto_verify_email",
        "auto_approve_application",
        "account_linking_enabled",
        "use_pkce",
        "enabled",
    )
    drifted = [k for k in drift_keys if existing.get(k) != desired.get(k)]
    if not drifted:
        print(
            f"[bootstrap] OAuth provider {PROVIDER_DISPLAY!r} already up "
            f"to date (id={existing.get('id')})"
        )
        return

    print(
        f"[bootstrap] reconciling OAuth provider {PROVIDER_DISPLAY!r} "
        f"(id={existing.get('id')}) — drifted fields: {drifted}"
    )
    update_body: dict = {"id": existing["id"], **desired}
    # ``client_id`` and ``display_name`` cannot be updated through
    # the standard PUT path on some Lemmy versions; the safe set is
    # whatever's in ``drift_keys`` above plus ``client_secret``.
    # We pass the full desired payload and let Lemmy ignore fields
    # it considers immutable.
    status, payload = _request("PUT", "/oauth_provider", update_body, auth=jwt_token)
    if status >= 400:
        print(
            f"[bootstrap] FATAL: oauth_provider update returned "
            f"status={status} payload={payload!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"[bootstrap] OAuth provider reconciled (id={existing.get('id')})")


def _ensure_open_registration(jwt_token: str, local_site: dict) -> None:
    """Set ``registration_mode = open`` if it isn't already.

    The OIDC user-creation path through ``/oauth/authenticate``
    creates a new Lemmy user the first time a given OIDC ``sub`` is
    seen.  When ``registration_mode = require_application`` the
    creation is rejected with ``registration_application_answer_required``
    because the OIDC flow has no field to carry the
    application-question answer.  ``open`` is correct for a
    single-tenant openhost-lemmy where only the zone owner ever
    signs in via SSO; remote federated users on other instances are
    not affected by this setting.
    """
    if local_site.get("registration_mode") == "open":
        print("[bootstrap] registration_mode is already 'open'")
        return

    print(
        f"[bootstrap] flipping registration_mode "
        f"({local_site.get('registration_mode')!r} -> 'open') so OIDC user "
        f"creation can complete without an application answer"
    )
    status, payload = _request(
        "PUT",
        "/site",
        {"registration_mode": "open"},
        auth=jwt_token,
    )
    if status >= 400:
        print(
            f"[bootstrap] FATAL: PUT /site (registration_mode) returned "
            f"status={status} payload={payload!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)


def _find_person_id(jwt_token: str, username: str) -> int | None:
    """Look up a local person's id by username.  Returns None if no
    such user exists yet.

    Lemmy 1.0 exposes this as ``GET /api/v4/person?username=<name>``.
    The 0.19.x naming was ``GET /api/v3/user?username=...`` — the
    rename to ``person`` shipped with the 1.0-alpha API surface.
    """
    status, payload = _request(
        "GET", f"/person?username={username}", auth=jwt_token
    )
    if status != 200:
        return None
    person = payload.get("person_view", {}).get("person", {})
    pid = person.get("id")
    return int(pid) if pid is not None else None


def _ensure_admin(jwt_token: str, admins: list[dict]) -> None:
    """Promote ``SSO_USERNAME`` to admin if the user exists and isn't
    already an admin.  No-op on the first boot before any SSO
    sign-in has created the user."""
    if any(a.get("person", {}).get("name") == SSO_USERNAME for a in admins):
        print(f"[bootstrap] {SSO_USERNAME!r} is already an admin")
        return

    person_id = _find_person_id(jwt_token, SSO_USERNAME)
    if person_id is None:
        print(
            f"[bootstrap] {SSO_USERNAME!r} user does not exist yet "
            f"(will be created on first SSO sign-in); skipping admin promotion"
        )
        return

    print(f"[bootstrap] promoting {SSO_USERNAME!r} (person_id={person_id}) to admin")
    status, payload = _request(
        "POST",
        "/admin/add",
        {"added": True, "person_id": person_id},
        auth=jwt_token,
    )
    if status >= 400:
        # Don't fail the bootstrap — the SSO user will still be able
        # to log in, just without admin rights.  Print enough for the
        # operator to debug, then continue.
        print(
            f"[bootstrap] WARN: admin/add returned status={status} payload={payload!r}; "
            f"the {SSO_USERNAME!r} user can sign in but is not an admin",
            file=sys.stderr,
        )
        return
    print(f"[bootstrap] {SSO_USERNAME!r} promoted to admin")


def _watch_for_sso_user_and_promote(
    jwt_token: str,
    poll_interval_seconds: int = 30,
    max_seconds: int = 24 * 60 * 60,
) -> None:
    """After initial reconciliation, stay alive polling for the
    ``SSO_USERNAME`` user and promote them to admin once they appear.

    The user is created lazily on the operator's first SSO sign-in,
    which can happen any time after the container starts.  Polling
    once per ``poll_interval_seconds`` is a low-cost way to bridge
    that gap without coupling the OIDC bridge to the Lemmy admin API
    (which would require giving the bridge access to the admin
    password).  Exits cleanly once the user is promoted; bounded by
    ``max_seconds`` so a deployment where SSO is never used doesn't
    leave us spinning forever.

    The admin JWT we got at boot stays valid for Lemmy's default
    24h, so this loop works without re-authentication for the
    full ``max_seconds`` window.  If the deployment runs longer
    than that without an SSO sign-in, the next container restart
    re-enters this loop with a fresh JWT.
    """
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        site = _site(jwt_token)
        admins = site.get("admins") or []
        if any(a.get("person", {}).get("name") == SSO_USERNAME for a in admins):
            print(f"[bootstrap] {SSO_USERNAME!r} is admin; watcher exiting")
            return
        person_id = _find_person_id(jwt_token, SSO_USERNAME)
        if person_id is not None:
            print(f"[bootstrap] {SSO_USERNAME!r} appeared (person_id={person_id}); promoting")
            status, payload = _request(
                "POST",
                "/admin/add",
                {"added": True, "person_id": person_id},
                auth=jwt_token,
            )
            if status >= 400:
                print(
                    f"[bootstrap] WARN: admin/add returned status={status} "
                    f"payload={payload!r}; will retry on next iteration",
                    file=sys.stderr,
                )
            else:
                print(f"[bootstrap] {SSO_USERNAME!r} promoted to admin; watcher exiting")
                return
        time.sleep(poll_interval_seconds)
    print(
        f"[bootstrap] watcher window of {max_seconds}s elapsed without seeing "
        f"{SSO_USERNAME!r}; will be re-tried on the next container restart"
    )


def main() -> int:
    _wait_for_lemmy()
    # Re-stamp the owner's bcrypt password to match the ephemeral
    # in-memory ADMIN_PASSWORD before we try to log in — on boots
    # after the first, the DB otherwise still has the previous
    # boot's password and the login below would 401.
    _reset_admin_password_in_db()
    jwt_token = _login()
    site = _site(jwt_token)

    providers = site.get("admin_oauth_providers") or []
    _reconcile_provider(jwt_token, providers)

    local_site = site.get("site_view", {}).get("local_site", {})
    _ensure_open_registration(jwt_token, local_site)

    admins = site.get("admins") or []
    _ensure_admin(jwt_token, admins)

    # If the SSO user already exists and is admin, we're done.
    # Otherwise, hang around polling for them to appear so we can
    # auto-promote on first SSO sign-in.
    if not any(a.get("person", {}).get("name") == SSO_USERNAME for a in admins):
        _watch_for_sso_user_and_promote(jwt_token)

    print("[bootstrap] done")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[bootstrap] uncaught exception: {exc}", file=sys.stderr)
        sys.exit(1)
