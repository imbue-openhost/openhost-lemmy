#!/usr/bin/env python3
"""First-boot OIDC-provider registration for openhost-lemmy.

Lemmy's setup.admin_username/admin_password creates an admin user
on first start.  After Lemmy is up, we:

  1. Log in to the admin via the configured password to mint a JWT.
  2. List existing OAuth providers; if the OpenHost provider is
     already registered, we're done.
  3. POST /api/v3/oauth_provider with the OIDC discovery details +
     OPENHOST_OIDC_CLIENT_ID / OPENHOST_OIDC_CLIENT_SECRET.

Idempotent; safe to run on every container start.

Configuration via env:
  * LEMMY_API_URL         — http://127.0.0.1:8536/api/v3
  * LEMMY_HOSTNAME        — public hostname (e.g. lemmy.<zone>)
  * LEMMY_ADMIN_PASSWORD  — admin password from config.hjson
  * OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, OIDC_PUBLIC_BASE
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

LEMMY_API = os.environ.get("LEMMY_API_URL", "http://127.0.0.1:8536/api/v3").rstrip("/")
LEMMY_HOSTNAME = os.environ["LEMMY_HOSTNAME"]
ADMIN_USERNAME = os.environ.get("LEMMY_ADMIN_USERNAME", "owner")
ADMIN_PASSWORD = os.environ["LEMMY_ADMIN_PASSWORD"]
OIDC_CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
OIDC_CLIENT_SECRET = os.environ["OIDC_CLIENT_SECRET"]
OIDC_PUBLIC_BASE = os.environ["OIDC_PUBLIC_BASE"].rstrip("/")
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
    """Poll /api/v3/site until Lemmy responds.  Used by start.sh
    before invoking us, but also from within so a slow first-boot
    migration doesn't trip us up."""
    deadline = time.time() + max_seconds
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{LEMMY_API}/site", timeout=5) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    raise SystemExit("[bootstrap] timed out waiting for Lemmy /api/v3/site")


def _login() -> str:
    print("[bootstrap] logging in as admin")
    status, payload = _request(
        "POST",
        "/user/login",
        {"username_or_email": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
    )
    if status != 200 or "jwt" not in payload:
        print(
            f"[bootstrap] FATAL: admin login returned status={status} payload={payload!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return payload["jwt"]


def _existing_providers(jwt_token: str) -> list[dict]:
    # Admin OAuth providers are returned by /site for admins.
    status, payload = _request("GET", "/site", auth=jwt_token)
    if status != 200:
        return []
    return payload.get("admin_oauth_providers") or []


def _register_provider(jwt_token: str) -> None:
    body = {
        "display_name": PROVIDER_DISPLAY,
        "issuer": f"{OIDC_PUBLIC_BASE}/_oidc",
        "authorization_endpoint": f"{OIDC_PUBLIC_BASE}/_oidc/authorize",
        "token_endpoint": f"{OIDC_PUBLIC_BASE}/_oidc/token",
        "userinfo_endpoint": f"{OIDC_PUBLIC_BASE}/_oidc/userinfo",
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
    print("[bootstrap] registering OpenHost OAuth provider")
    status, payload = _request("POST", "/oauth_provider", body, auth=jwt_token)
    if status >= 400:
        print(
            f"[bootstrap] FATAL: oauth_provider create returned "
            f"status={status} payload={payload!r}",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"[bootstrap] OAuth provider registered: {payload}")


def main() -> int:
    _wait_for_lemmy()
    jwt_token = _login()
    providers = _existing_providers(jwt_token)
    matching = [p for p in providers if p.get("display_name") == PROVIDER_DISPLAY]
    if matching:
        print(
            f"[bootstrap] OAuth provider {PROVIDER_DISPLAY!r} already exists "
            f"(id={matching[0].get('id')}); nothing to do"
        )
        return 0
    _register_provider(jwt_token)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        print(f"[bootstrap] uncaught exception: {exc}", file=sys.stderr)
        sys.exit(1)
