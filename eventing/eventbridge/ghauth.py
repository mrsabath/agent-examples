"""GitHub sign-in for the submit path: device flow, then who the token belongs to.

Stdlib only (`urllib`), as §1.1 requires.

**GitHub does not issue a verifiable token for user login.** The device flow
returns an *opaque* access token — no signature, no claims, nothing to check
offline. (The JWKS at `token.actions.githubusercontent.com` is for Actions
workloads, not users.) So EventBridge cannot verify a token locally; it has to
ask GitHub who holds it, via `GET /user`.

Three consequences, all deliberate rather than accidental:

* **Sign-in depends on GitHub being reachable.** A failed lookup is a `401`, not
  an allow. Failing closed is the only safe direction when the question is "who
  is this".
* **The cache is load-bearing, not an optimisation.** Without it every request
  costs an API call against a 5000/hour budget. It is keyed by a hash of the
  token, never the token, so a memory dump or a log line cannot yield a working
  credential.
* **No scopes are requested.** `GET /user` returns the login for an unscoped
  token, so the app asks for the least access that answers the question. Nothing
  here can read a repository.

The approved-user list is separate from authentication on purpose: `401` means
"I do not know you", `403` means "I know you and you are not on the list". Those
are different answers and collapsing them tells an operator less.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request

DEVICE_CODE_URL = "https://github.com/login/device/code"
ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"
VERIFICATION_URL = "https://github.com/login/device"

# GitHub's own default poll interval, used when a response omits one.
DEFAULT_INTERVAL_S = 5
# Added to the interval when GitHub answers `slow_down`, as its docs specify.
SLOW_DOWN_PENALTY_S = 5

_UA = "rossoctl-eventing"


def _post_form(url: str, fields: dict[str, str], timeout: float) -> dict:
    """POST a form, read JSON back. GitHub returns form-encoded unless asked."""
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Accept": "application/json", "User-Agent": _UA,
                 "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


# ---- device flow (the CLI side) ---------------------------------------------

def start_device_flow(client_id: str, *, timeout: float = 10.0) -> dict:
    """Ask GitHub for a device code and the code the user will type.

    Returns GitHub's response: `device_code`, `user_code`, `verification_uri`,
    `expires_in`, `interval`. Raises `RuntimeError` on `device_flow_disabled`,
    which means the app exists but device flow was never ticked on — the single
    most common setup mistake, so it gets its own message.
    """
    out = _post_form(DEVICE_CODE_URL,
                     # An empty scope is deliberate: see the module docstring.
                     {"client_id": client_id, "scope": ""}, timeout)
    if "error" in out:
        err = out.get("error")
        if err == "device_flow_disabled":
            raise RuntimeError(
                "this OAuth App does not have Device Flow enabled — tick "
                "'Enable Device Flow' on the app page at "
                "https://github.com/settings/developers")
        raise RuntimeError(f"GitHub refused the device code request: {err} "
                           f"({out.get('error_description', 'no detail')})")
    if not out.get("device_code") or not out.get("user_code"):
        raise RuntimeError(f"unexpected device code response: {out!r}")
    return out


def poll_for_token(client_id: str, device_code: str, *, interval: float | None = None,
                   expires_in: float = 900.0, timeout: float = 10.0,
                   sleep=time.sleep, now=time.monotonic) -> str:
    """Poll until the user authorises, then return the access token.

    Honours GitHub's pacing contract: `authorization_pending` means keep going,
    `slow_down` means keep going but add five seconds. Polling faster than asked
    gets the app rate-limited, which would break sign-in for everyone rather than
    just this caller.

    `sleep` and `now` are injectable so tests exercise the pacing without
    actually waiting.
    """
    wait = float(interval or DEFAULT_INTERVAL_S)
    deadline = now() + expires_in
    while True:
        if now() >= deadline:
            raise TimeoutError(
                "the device code expired before it was authorised — run login again")
        sleep(wait)
        out = _post_form(ACCESS_TOKEN_URL, {
            "client_id": client_id, "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }, timeout)
        token = out.get("access_token")
        if token:
            return str(token)
        err = out.get("error")
        if err == "authorization_pending":
            continue
        if err == "slow_down":
            wait = float(out.get("interval", wait)) + SLOW_DOWN_PENALTY_S
            continue
        if err == "expired_token":
            raise TimeoutError(
                "the device code expired before it was authorised — run login again")
        if err == "access_denied":
            raise RuntimeError("sign-in was declined in the browser")
        raise RuntimeError(f"GitHub refused the token request: {err} "
                           f"({out.get('error_description', 'no detail')})")


# ---- resolving a token to a login (the server side) -------------------------

def _token_key(token: str) -> str:
    """Cache key. A hash, so the cache never holds a usable credential."""
    return hashlib.sha256(token.encode()).hexdigest()


def fetch_login(token: str, *, timeout: float = 5.0) -> tuple[str | None, str | None]:
    """`GET /user` -> `(login, error)`. Exactly one is None.

    A 401 from GitHub means the token is unknown or revoked, which is the
    caller's problem and safe to report. Anything else — a network failure, a 500,
    a rate limit — is ours, and is reported as an unavailability rather than a
    rejection, because telling a legitimate user "invalid credential" when
    GitHub was merely unreachable sends them debugging the wrong thing.
    """
    req = urllib.request.Request(
        USER_URL, headers={"Authorization": f"Bearer {token}",
                           "Accept": "application/vnd.github+json",
                           "User-Agent": _UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return None, "GitHub rejected this token"
        if e.code == 403:
            return None, "GitHub rate limit or access restriction (403)"
        return None, f"GitHub returned HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — urllib raises a wide family here
        return None, f"cannot reach GitHub: {e.__class__.__name__}"
    login = body.get("login")
    if not isinstance(login, str) or not login:
        return None, "GitHub returned no login for this token"
    return login, None


class LoginCache:
    """Token hash -> login, with a TTL.

    Not an optimisation: without it every submitted request spends one of 5000
    hourly API calls, and adds GitHub's latency to the request path. Entries are
    keyed by hash so the cache cannot be read back into a working credential.

    Negative results are not cached. A revoked token must stop working promptly,
    and a GitHub outage must not pin a legitimate user to a failure for the whole
    TTL.
    """

    def __init__(self, ttl_s: float = 300.0, now=time.monotonic) -> None:
        self._ttl = float(ttl_s)
        self._now = now
        self._entries: dict[str, tuple[float, str]] = {}

    def get(self, token: str) -> str | None:
        hit = self._entries.get(_token_key(token))
        if hit is None:
            return None
        expires, login = hit
        if self._now() >= expires:
            self._entries.pop(_token_key(token), None)
            return None
        return login

    def put(self, token: str, login: str) -> None:
        self._entries[_token_key(token)] = (self._now() + self._ttl, login)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def resolve(token: str, cache: LoginCache | None = None, *,
            fetch=fetch_login) -> tuple[str | None, str | None]:
    """Token -> `(login, error)`, consulting the cache first."""
    if cache is not None:
        cached = cache.get(token)
        if cached is not None:
            return cached, None
    login, err = fetch(token)
    if login and cache is not None:
        cache.put(token, login)
    return login, err


def parse_allowed_users(raw: str) -> frozenset[str]:
    """`"alice, bob"` -> `{"alice", "bob"}`, compared case-insensitively.

    GitHub logins are case-insensitive, so `Alice` and `alice` are one account.
    Comparing case-sensitively would let a real approved user be refused because
    of how they typed it, which reads as a broken deployment.
    """
    return frozenset(u.strip().lower() for u in raw.split(",") if u.strip())


def is_allowed(login: str, allowed: frozenset[str]) -> bool:
    """Empty list means nobody is approved — deny.

    The alternative reading, "empty means everybody", would turn a missing
    environment variable into an open door. If GitHub sign-in is configured at
    all, the operator must say who may use it.
    """
    return login.lower() in allowed
