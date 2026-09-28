"""GitHub sign-in: device flow, token -> login, and the approved-user list.

No test here touches the network. The device flow and `GET /user` are exercised
through injected fakes, because a test suite that reaches GitHub would be slow,
flaky, rate-limited, and would fail entirely on a machine without credentials.
"""
from __future__ import annotations

import io
import json

import pytest
from eventbridge import auth, ghauth
from eventbridge.config import Cfg as EbCfg

# ---- the approved-user list -------------------------------------------------

def test_parse_allowed_users_splits_and_lowercases():
    assert ghauth.parse_allowed_users("Alice, BOB ,carol") == {"alice", "bob", "carol"}


def test_parse_allowed_users_ignores_blanks():
    assert ghauth.parse_allowed_users(" , ,alice, ") == {"alice"}


def test_parse_allowed_users_empty_is_empty():
    assert ghauth.parse_allowed_users("") == frozenset()


def test_is_allowed_is_case_insensitive():
    """GitHub logins are case-insensitive, so Alice and alice are one account.
    Comparing case-sensitively would refuse a genuinely approved user."""
    allowed = ghauth.parse_allowed_users("mrsabath")
    assert ghauth.is_allowed("mrsabath", allowed)
    assert ghauth.is_allowed("MrSabath", allowed)
    assert ghauth.is_allowed("MRSABATH", allowed)


def test_is_allowed_denies_when_the_list_is_empty():
    """The other reading — "empty means everybody" — would turn a missing
    environment variable into an open door."""
    assert not ghauth.is_allowed("anyone", frozenset())


def test_is_allowed_denies_a_non_member():
    assert not ghauth.is_allowed("stranger", ghauth.parse_allowed_users("alice,bob"))


# ---- the login cache --------------------------------------------------------

class FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def test_cache_returns_what_was_put():
    c = ghauth.LoginCache(300.0, now=FakeClock())
    c.put("tok", "alice")
    assert c.get("tok") == "alice"


def test_cache_misses_an_unknown_token():
    assert ghauth.LoginCache(300.0).get("nope") is None


def test_cache_entry_expires():
    clock = FakeClock()
    c = ghauth.LoginCache(300.0, now=clock)
    c.put("tok", "alice")
    clock.advance(299)
    assert c.get("tok") == "alice"
    clock.advance(2)
    assert c.get("tok") is None


def test_cache_never_stores_the_token_itself():
    """A memory dump or a careless log of the cache must not yield a credential."""
    c = ghauth.LoginCache(300.0)
    c.put("gho_supersecret", "alice")
    assert "gho_supersecret" not in repr(c.__dict__)
    assert all("gho_supersecret" not in k for k in c._entries)


def test_cache_separates_distinct_tokens():
    c = ghauth.LoginCache(300.0)
    c.put("tok-a", "alice")
    c.put("tok-b", "bob")
    assert (c.get("tok-a"), c.get("tok-b")) == ("alice", "bob")


# ---- resolve (cache + fetch) ------------------------------------------------

def test_resolve_uses_the_cache_and_does_not_refetch():
    calls = []

    def fetch(token):
        calls.append(token)
        return "alice", None

    c = ghauth.LoginCache(300.0)
    assert ghauth.resolve("tok", c, fetch=fetch) == ("alice", None)
    assert ghauth.resolve("tok", c, fetch=fetch) == ("alice", None)
    assert len(calls) == 1, "second call should have been served from the cache"


def test_resolve_does_not_cache_a_failure():
    """A revoked token must stop working promptly, and a GitHub outage must not
    pin a legitimate user to a failure for the whole TTL."""
    c = ghauth.LoginCache(300.0)
    ghauth.resolve("tok", c, fetch=lambda t: (None, "GitHub rejected this token"))
    assert len(c) == 0


def test_resolve_works_without_a_cache():
    assert ghauth.resolve("tok", None, fetch=lambda t: ("bob", None)) == ("bob", None)


# ---- fetch_login error mapping ---------------------------------------------

class FakeHTTPError(Exception):
    def __init__(self, code):
        self.code = code


def _patched_fetch(monkeypatch, *, raises=None, body=None):
    import urllib.error

    class _Err(urllib.error.HTTPError):
        def __init__(self, code):
            self.code = code  # bypass HTTPError's heavy __init__

    def fake_urlopen(req, timeout=None):
        if raises is not None:
            raise _Err(raises)

        class _R:
            def read(self_inner):
                return json.dumps(body or {}).encode()

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False
        return _R()

    monkeypatch.setattr(ghauth.urllib.request, "urlopen", fake_urlopen)


def test_fetch_login_returns_the_login(monkeypatch):
    _patched_fetch(monkeypatch, body={"login": "mrsabath"})
    assert ghauth.fetch_login("tok") == ("mrsabath", None)


def test_fetch_login_401_is_reported_as_a_rejection(monkeypatch):
    _patched_fetch(monkeypatch, raises=401)
    login, err = ghauth.fetch_login("tok")
    assert login is None and "rejected" in err


def test_fetch_login_403_mentions_the_rate_limit(monkeypatch):
    _patched_fetch(monkeypatch, raises=403)
    login, err = ghauth.fetch_login("tok")
    assert login is None and "rate limit" in err


def test_fetch_login_500_is_not_reported_as_a_bad_credential(monkeypatch):
    """Telling a legitimate user "invalid credential" when GitHub was merely
    broken sends them debugging the wrong thing."""
    _patched_fetch(monkeypatch, raises=500)
    login, err = ghauth.fetch_login("tok")
    assert login is None
    assert "rejected" not in err and "500" in err


def test_fetch_login_network_failure_says_unreachable(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("dns go boom")
    monkeypatch.setattr(ghauth.urllib.request, "urlopen", boom)
    login, err = ghauth.fetch_login("tok")
    assert login is None and "cannot reach GitHub" in err


def test_fetch_login_missing_login_field(monkeypatch):
    _patched_fetch(monkeypatch, body={"id": 1})
    login, err = ghauth.fetch_login("tok")
    assert login is None and "no login" in err


# ---- device flow ------------------------------------------------------------

def _patch_post(monkeypatch, responses):
    """Serve queued JSON responses to `_post_form`, recording the URLs called."""
    seen = []

    def fake_post(url, fields, timeout):
        seen.append((url, fields))
        return responses.pop(0)

    monkeypatch.setattr(ghauth, "_post_form", fake_post)
    return seen


def test_start_device_flow_returns_the_codes(monkeypatch):
    seen = _patch_post(monkeypatch, [{
        "device_code": "dc", "user_code": "WDJB-MJHT",
        "verification_uri": ghauth.VERIFICATION_URL, "expires_in": 900, "interval": 5}])
    out = ghauth.start_device_flow("cid")
    assert out["user_code"] == "WDJB-MJHT"
    assert seen[0][0] == ghauth.DEVICE_CODE_URL


def test_start_device_flow_requests_no_scopes(monkeypatch):
    """Least access that answers "who is this": GET /user needs no scope."""
    seen = _patch_post(monkeypatch, [{"device_code": "dc", "user_code": "U"}])
    ghauth.start_device_flow("cid")
    assert seen[0][1]["scope"] == ""


def test_start_device_flow_explains_device_flow_disabled(monkeypatch):
    """The single most common setup mistake, so it gets its own message."""
    _patch_post(monkeypatch, [{"error": "device_flow_disabled"}])
    with pytest.raises(RuntimeError, match="Enable Device Flow"):
        ghauth.start_device_flow("cid")


def test_start_device_flow_reports_other_errors(monkeypatch):
    _patch_post(monkeypatch, [{"error": "unauthorized_client",
                               "error_description": "bad client"}])
    with pytest.raises(RuntimeError, match="unauthorized_client"):
        ghauth.start_device_flow("cid")


def test_poll_returns_the_token_once_authorised(monkeypatch):
    _patch_post(monkeypatch, [
        {"error": "authorization_pending"},
        {"error": "authorization_pending"},
        {"access_token": "gho_abc"},
    ])
    slept = []
    tok = ghauth.poll_for_token("cid", "dc", interval=5, sleep=slept.append)
    assert tok == "gho_abc"
    assert slept == [5.0, 5.0, 5.0]


def test_poll_honours_slow_down_by_adding_five_seconds(monkeypatch):
    """Polling faster than GitHub asks rate-limits the whole app, not just us."""
    _patch_post(monkeypatch, [
        {"error": "slow_down", "interval": 5},
        {"access_token": "gho_abc"},
    ])
    slept = []
    ghauth.poll_for_token("cid", "dc", interval=5, sleep=slept.append)
    assert slept == [5.0, 10.0]


def test_poll_raises_on_expired_token(monkeypatch):
    _patch_post(monkeypatch, [{"error": "expired_token"}])
    with pytest.raises(TimeoutError, match="expired"):
        ghauth.poll_for_token("cid", "dc", interval=1, sleep=lambda s: None)


def test_poll_raises_when_the_user_declines(monkeypatch):
    _patch_post(monkeypatch, [{"error": "access_denied"}])
    with pytest.raises(RuntimeError, match="declined"):
        ghauth.poll_for_token("cid", "dc", interval=1, sleep=lambda s: None)


def test_poll_gives_up_at_the_deadline(monkeypatch):
    _patch_post(monkeypatch, [{"error": "authorization_pending"}] * 50)
    clock = FakeClock()

    def sleep(dt):
        clock.advance(dt)

    with pytest.raises(TimeoutError):
        ghauth.poll_for_token("cid", "dc", interval=5, expires_in=20,
                              sleep=sleep, now=clock)


# ---- auth.resolve: the 401 / 403 distinction -------------------------------

def _env(token: str | None = None) -> dict:
    e = {"wsgi.input": io.BytesIO(b""), "REQUEST_METHOD": "POST"}
    if token:
        e["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return e


def _cfg(**kw) -> EbCfg:
    return EbCfg(tmpdir="/tmp/x", **kw)


def test_resolve_allows_anonymous_when_nothing_is_configured():
    ident, iss, status, why = auth.resolve(_env(), _cfg())
    assert (ident, iss, status, why) == (None, None, None, None)


def test_resolve_401_without_a_credential_when_github_is_on():
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"alice"}))
    ident, iss, status, why = auth.resolve(_env(), cfg)
    assert status == 401 and ident is None


def test_resolve_401_when_github_rejects_the_token():
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"alice"}))
    ident, iss, status, why = auth.resolve(
        _env("bad"), cfg, fetch=lambda t: (None, "GitHub rejected this token"))
    assert status == 401 and "rejected" in why


def test_resolve_403_for_a_real_user_who_is_not_approved():
    """The demo-worthy case: authenticated, and still refused."""
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"alice"}))
    ident, iss, status, why = auth.resolve(
        _env("gho_x"), cfg, fetch=lambda t: ("mallory", None))
    assert status == 403
    assert "mallory" in why, "the refusal should name the identity it refused"
    assert ident is None


def test_resolve_allows_an_approved_user_and_records_the_issuer():
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"mrsabath"}))
    ident, iss, status, why = auth.resolve(
        _env("gho_x"), cfg, fetch=lambda t: ("mrsabath", None))
    assert (ident, iss, status) == ("mrsabath", "github", None)


def test_resolve_is_case_insensitive_about_the_approved_login():
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"mrsabath"}))
    ident, _, status, _ = auth.resolve(
        _env("gho_x"), cfg, fetch=lambda t: ("MrSabath", None))
    assert status is None and ident == "MrSabath"


def test_a_static_token_still_works_as_a_break_glass_credential():
    """An operator keeping one alongside GitHub sign-in should not be locked out
    when GitHub is unreachable."""
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"alice"}),
               auth_tokens={"emergency": "operator"})
    ident, iss, status, _ = auth.resolve(
        _env("emergency"), cfg, fetch=lambda t: (None, "cannot reach GitHub: OSError"))
    assert (ident, iss, status) == ("operator", None, None)


def test_static_token_path_reports_no_issuer():
    """Absence of an issuer is the signal that this identity was not verified."""
    cfg = _cfg(auth_tokens={"tok": "alice"})
    ident, iss, status, _ = auth.resolve(_env("tok"), cfg)
    assert (ident, iss, status) == ("alice", None, None)


def test_resolve_401_for_a_wrong_static_token():
    cfg = _cfg(auth_tokens={"tok": "alice"})
    _, _, status, _ = auth.resolve(_env("wrong"), cfg)
    assert status == 401


def test_github_on_with_only_an_allowed_list_still_enforces():
    """Setting the list but forgetting the client id must not silently allow."""
    cfg = _cfg(allowed_users=frozenset({"alice"}))
    _, _, status, _ = auth.resolve(_env(), cfg)
    assert status == 401


def test_the_cache_means_one_github_call_for_repeated_requests():
    calls = []
    cfg = _cfg(github_client_id="cid", allowed_users=frozenset({"alice"}))
    cache = ghauth.LoginCache(300.0)

    def fetch(token):
        calls.append(token)
        return "alice", None

    for _ in range(5):
        ident, _, status, _ = auth.resolve(_env("gho_x"), cfg, cache=cache, fetch=fetch)
        assert status is None and ident == "alice"
    assert len(calls) == 1
