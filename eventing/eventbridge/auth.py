"""Bearer-token identity for the submit path. Stdlib only.

Scope is deliberately narrow: this answers "who is asking me to run an agent?"
on the two routes that CREATE work. It is not a general authorization layer.

Two mechanisms live here. `ghauth` verifies a GitHub sign-in and is the real
path; the static token map below is the fallback that keeps tests off the network
and an offline demo possible. `resolve()` is the entry point that picks.

Two properties worth stating, because both are easy to get wrong:

* **Constant-time comparison.** Tokens are compared with
  `hmac.compare_digest`, not `==`. A short-circuiting compare leaks the shared
  prefix length through timing, which over enough requests recovers the token
  one byte at a time.
* **Identity is a name, not a boolean.** The config maps a name to each token,
  so a validated request yields `"alice"` rather than `True`. That name rides
  onto the request event as `ce_submitter`, which is the whole point — a `401`
  tells you nothing after the fact, a recorded submitter does.

What this is NOT: the submitter attribute is **unsigned**. Anyone who can write
to the Kafka `requests` topic can forge it, and the broker is plaintext. The
honest claim is "EventBridge refuses unauthenticated submissions and records who
it believes submitted this" — not "this event proves who submitted it." Proving
it needs `submitter` inside `signing.SIGNED_ATTRS` and a producer that actually
signs (today nothing does; see agentdocs/IMPLEMENTATION_REPORT1.md §811-814).
"""
from __future__ import annotations

import hmac
from typing import Any

# Returned verbatim as the `WWW-Authenticate` value on a 401 so a client knows
# which scheme to retry with.
CHALLENGE = 'Bearer realm="eventbridge"'


def parse_tokens(raw: str) -> dict[str, str]:
    """`"alice:tok1,bob:tok2"` -> `{"tok1": "alice", "tok2": "bob"}`.

    Keyed by token because lookup goes token -> name. Malformed entries (no
    colon, empty name, empty token) are skipped rather than raising: a typo in
    one entry must not take the whole service down at startup, and a skipped
    entry fails closed — that token simply does not authenticate.
    """
    out: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            continue
        name, _, token = entry.partition(":")
        name, token = name.strip(), token.strip()
        if name and token:
            out[token] = name
    return out


def _bearer(environ: dict[str, Any]) -> tuple[str | None, str | None]:
    """Pull the bearer token out of the environ. `(token, error)`.

    Reads only headers. It must not touch `wsgi.input`: `handlers._read_json`
    reads the body from a non-seekable stream, so consuming it here would leave
    every downstream handler with an empty body.
    """
    header = environ.get("HTTP_AUTHORIZATION") or ""
    if not header:
        return None, "authentication required"
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer":
        return None, "unsupported authentication scheme; expected Bearer"
    presented = presented.strip()
    if not presented:
        return None, "empty bearer token"
    return presented, None


def resolve_identity(environ: dict[str, Any], tokens: dict[str, str]) -> tuple[str | None, str | None]:
    """Resolve the caller from a static token map.

    Returns `(identity, error)`:

    * `(None, None)`   — auth is disabled (no tokens configured). Callers treat
                         this as "allowed, anonymous", which keeps the default
                         demo path working unchanged.
    * `(name, None)`   — a valid credential for `name`.
    * `(None, reason)` — reject with 401; `reason` is safe to return to the
                         client (it never echoes the presented token).
    """
    if not tokens:
        return None, None

    presented, why = _bearer(environ)
    if why:
        return None, why

    # Compare against every configured token so the work done is independent of
    # which entry matches (and of whether any does). `compare_digest` on str
    # requires ASCII, so a non-ASCII token is rejected rather than raising.
    try:
        matched = None
        for token, name in tokens.items():
            if hmac.compare_digest(token, presented):
                matched = name
    except TypeError:
        return None, "malformed bearer token"

    if matched is None:
        return None, "invalid bearer token"
    return matched, None


# ---- the combined entry point ----------------------------------------------

def resolve(environ: dict[str, Any], cfg, *, cache=None,
            fetch=None) -> tuple[str | None, str | None, int | None, str | None]:
    """Resolve the caller. `(identity, issuer, status, reason)` — handlers call this.

    `issuer` records *who vouched* for the identity: `"github"` for a verified
    sign-in, `None` for a static token. A reader of the event can then tell a
    real identity from a name an operator typed into an environment variable.

    `status` is the HTTP status to refuse with, and it carries real information:

    * `401` — "I do not know you": no credential, a malformed one, or one GitHub
      does not recognise.
    * `403` — "I know exactly who you are, and you are not approved." A real,
      authenticated person who is not on the list.

    Collapsing those into one answer would tell an operator less, and would tell
    a user debugging their own access much less.

    Two mechanisms, checked in order:

    1. **GitHub sign-in**, when a client id and an approved-user list are
       configured. The real path.
    2. **Static tokens** (`EB_AUTH_TOKENS`), as a fallback. Tests must not reach
       the network, and an offline demo has to stay possible, so this stays.

    With neither configured the result is all-`None` — allowed and
    anonymous, which is what keeps the default demo working out of the box.
    """
    from eventbridge import ghauth

    github_on = bool(getattr(cfg, "github_client_id", "")) or bool(
        getattr(cfg, "allowed_users", frozenset()))

    if github_on:
        presented, why = _bearer(environ)
        if why:
            # Fall back to a static token only when one could match; otherwise a
            # missing header is simply unauthenticated.
            if not cfg.auth_tokens:
                return None, None, 401, why
            name, why2 = resolve_identity(environ, cfg.auth_tokens)
            return (name, None, None, None) if name else (None, None, 401, why2)

        login, err = ghauth.resolve(
            presented, cache, **({"fetch": fetch} if fetch else {}))
        if login is None:
            # A static token is checked before giving up, so an operator can keep
            # a break-glass credential alongside GitHub sign-in.
            if cfg.auth_tokens:
                name, _ = resolve_identity(environ, cfg.auth_tokens)
                if name:
                    return name, None, None, None
            return None, None, 401, err or "could not identify this token"

        if not ghauth.is_allowed(login, cfg.allowed_users):
            # Name the login in the refusal: the user knows who they are, and
            # being told which identity was refused is what makes it actionable.
            return None, None, 403, f"{login} is not on the approved-user list"
        return login, "github", None, None

    name, why = resolve_identity(environ, cfg.auth_tokens)
    if why:
        return None, None, 401, why
    return name, None, None, None
