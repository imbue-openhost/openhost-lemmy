#!/usr/bin/env python3
"""SSO bouncer for openhost-lemmy.

Lemmy's frontend (lemmy-ui) kicks off OAuth via client-side JS that:

  1. Generates a UUIDv4 ``state``.
  2. Writes ``oauth_state`` to ``localStorage`` (containing
     ``state``, ``oauth_provider_id``, ``redirect_uri``,
     ``prev``, ``expires_at``, etc.).
  3. ``window.location.assign(<authorize-url>?...)``.

When the provider redirects back to ``/oauth/callback?code=...&state=...``
lemmy-ui's OAuthCallback component reads the same ``oauth_state``
from localStorage to recover ``oauth_provider_id`` + ``redirect_uri``
and POSTs to ``/api/v3/oauth/authenticate``.

A server-side 302 directly to ``<provider>/authorize`` would not
write to the browser's localStorage, so the callback rejects the
attempt as "missing state".  The bouncer therefore serves a tiny
HTML page that performs steps 1-3 in inline JS — the same
behaviour as if the visitor had clicked the ``Sign in with
OpenHost`` button on Lemmy's /login page.

The bouncer also enforces auth: only owner navigations
(``X-OpenHost-Is-Owner: true``) are served the bounce page; anyone
else gets a 302 to /login on the parent zone.

Run as: ``uvicorn sso_bounce:app --host 127.0.0.1 --port 7100``
"""

from __future__ import annotations

import html
import logging
import os
import uuid

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route

logger = logging.getLogger("openhost-lemmy.bounce")

PUBLIC_BASE = os.environ["OIDC_PUBLIC_BASE"].rstrip("/")
CLIENT_ID = os.environ["OIDC_CLIENT_ID"]
# Lemmy assigns oauth_provider_id automatically; the bootstrap
# script registers exactly one provider so id == 1 unless you
# delete and recreate it.  We pin to 1 here; if you rebuild the
# instance with multiple providers you'd need to change this or
# generalise the bouncer.
LEMMY_OAUTH_PROVIDER_ID = int(os.environ.get("LEMMY_OAUTH_PROVIDER_ID", "1"))
# Username the synthetic SSO user takes on first sign-in.  Must
# match what bootstrap.py promotes to admin (its SSO_USERNAME env
# var); we coordinate via the same env var name so an operator who
# changes one updates both.  Cannot collide with the provisioning
# admin (``owner``) — Lemmy rejects an OAuth registration whose
# username is already taken.  See bootstrap.py for the fuller
# rationale on why we use a separate user instead of linking to
# ``owner``.
SSO_USERNAME = os.environ.get("SSO_USERNAME", "openhost")


def _is_owner(request: Request) -> bool:
    return request.headers.get("X-OpenHost-Is-Owner", "").lower() == "true"


def _bare_zone(request: Request) -> str:
    """Compute the zone domain (without the per-app subdomain).

    The X-Forwarded-Host the OpenHost router sets is the public
    hostname of THIS app — e.g. ``lemmy.<zone>``.  Strip the
    leading subdomain to land on ``<zone>``.
    """
    host = request.headers.get("X-Forwarded-Host", request.url.netloc)
    return host.split(".", 1)[1] if "." in host else host


def _redirect_uri(request: Request) -> str:
    """The redirect_uri Lemmy expects: ``<this app>/oauth/callback``.

    Must match what lemmy-ui would have sent and must equal what
    the lemmy backend's authenticate_with_oauth strictly validates.
    """
    host = request.headers.get("X-Forwarded-Host", request.url.netloc)
    return f"https://{host}/oauth/callback"


async def bounce(request: Request) -> Response:
    if not _is_owner(request):
        # Not the owner: punt to the zone /login.  Whatever they
        # were trying to reach was a Lemmy public path that
        # lemmy-ui SSR will render server-side; subsequent
        # requests after they sign in will go to /sso-bounce
        # again with the owner header set.
        return RedirectResponse(f"https://{_bare_zone(request)}/login", status_code=302)

    state = str(uuid.uuid4())
    expires_at = "Date.now() + 5 * 60 * 1000"  # JS expression
    redirect_uri = _redirect_uri(request)
    prev = request.query_params.get("prev", "/")
    # Constrain prev to a same-origin path so we can't be tricked
    # into open-redirecting.
    if not prev.startswith("/"):
        prev = "/"

    authorize_url = (
        f"{PUBLIC_BASE}/_oidc/authorize"
        f"?client_id={CLIENT_ID}"
        f"&response_type=code"
        f"&scope=openid+email+profile"
        f"&redirect_uri={html.escape(redirect_uri, quote=True)}"
        f"&state={state}"
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Signing in to Lemmy via OpenHost SSO…</title>
  <style>
    body {{ font-family: -apple-system, system-ui, sans-serif;
            display:flex; min-height:100vh; align-items:center;
            justify-content:center; background:#1a1a1a; color:#ddd;
            margin:0; }}
    .card {{ text-align:center; padding:2em 3em; background:#222;
             border:1px solid #333; border-radius:8px;
             max-width:32em; }}
    .spinner {{ width:32px; height:32px; border:4px solid #444;
                border-top-color:#88f; border-radius:50%;
                animation:spin 1s linear infinite;
                margin:0 auto 1em; }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    code {{ background:#333; padding:0.1em 0.4em;
            border-radius:3px; }}
    a {{ color:#88f; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="spinner"></div>
    <p>Signing in to Lemmy via OpenHost SSO…</p>
    <p><small>If you aren't redirected,
       <a id="manual" href="">click here</a>.</small></p>
  </div>
  <script>
  (function() {{
    // Pre-fill the localStorage shape that lemmy-ui's OAuthCallback
    // component reads on the redirect-back leg.  ``username`` is
    // the dedicated SSO user we mint on first sign-in (see
    // bootstrap.py for why it's separate from the provisioning
    // admin user).  ``answer`` is left blank — Lemmy's
    // application-question gate is bypassed on this instance via
    // registration_mode=open (also set by bootstrap.py); on a
    // hypothetical operator override that re-enables
    // require_application, this would need to carry an actual
    // free-form answer.
    var oauthState = {{
      state: {state!r},
      oauth_provider_id: {LEMMY_OAUTH_PROVIDER_ID},
      redirect_uri: {redirect_uri!r},
      prev: {prev!r},
      username: {SSO_USERNAME!r},
      answer: undefined,
      show_nsfw: undefined,
      expires_at: {expires_at}
    }};
    try {{
      localStorage.setItem("oauth_state", JSON.stringify(oauthState));
    }} catch (e) {{
      // Disabled localStorage: still proceed; Lemmy's callback will
      // fail with "expired or missing state" and the visitor sees
      // the standard error page.  Better than a silent hang.
      console.error("openhost-lemmy: localStorage unavailable: " + e);
    }}
    var u = {authorize_url!r};
    document.getElementById("manual").href = u;
    window.location.replace(u);
  }})();
  </script>
</body>
</html>
"""
    # Cache-Control: no-store — bouncer must run on every visit so
    # we never serve a stale state.
    return HTMLResponse(page, headers={"Cache-Control": "no-store"})


routes = [
    Route("/sso-bounce", bounce),
]

app: Starlette = Starlette(debug=False, routes=routes)
