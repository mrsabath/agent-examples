"""Environment > config.toml > baked defaults. Stdlib only."""
from __future__ import annotations

import os
import pathlib
import tomllib
from dataclasses import dataclass, field

from eventbridge import auth, ghauth


@dataclass
class NtfyCfg:
    enabled: bool = True
    base_url: str = "https://ntfy.sh"
    topic: str = ""
    token: str = ""
    phases: tuple[str, ...] = ("result", "error")
    # §21.6/§21.9: notify on a group MEMBER's error even while the group is open.
    # Default false to match the brief as written; recommended true, because a
    # silently failing batch looks exactly like a healthy one until it ends.
    group_notify_errors: bool = False


@dataclass
class Cfg:
    kafka_bootstrap: str = "localhost:9092"
    request_topic: str = "requests"
    response_topic: str = "responses"
    http_addr: str = "127.0.0.1:8080"
    http_workers: int = 8
    public_base_url: str = "http://127.0.0.1:8080"
    source_uri: str = "rossoctl://eventbridge/local"
    tmpdir: str = ""
    # §16 Gap B / T1.8: cap on a checkpointed session transcript. A trivial
    # one-turn transcript already measures ~222 KB (the system prompt and tool
    # definitions dominate), so a small cap would reject the very first
    # checkpoint. 32 MiB is a very long conversation and still fits in memory.
    transcript_max_bytes: int = 32 * 1024 * 1024
    # §21.9.2 straggler cutoff. Without a deadline a group that is short one member
    # never completes, and therefore never sends its completion notification — the
    # failure mode is silence, which is the worst one. 0 disables.
    group_deadline_s: float = 3600.0
    # Bearer tokens for the submit path, as {token: name}. Empty disables auth
    # entirely, which is the default: the demo must keep working out of the box,
    # and a token is a capability that cannot be baked into a default. Supplied
    # only via EB_AUTH_TOKENS — deliberately never read from config.toml, which
    # is committed (tests/test_manifests.py pins the same rule for NTFY_TOKEN).
    auth_tokens: dict[str, str] = field(default_factory=dict)
    # GitHub sign-in. The client id is PUBLIC — the OAuth device flow has no
    # client secret, which is why it can be committed while an ntfy topic cannot.
    github_client_id: str = ""
    # Who may submit. Empty means nobody is approved: if GitHub sign-in is
    # configured at all, an operator has to say who may use it, because the other
    # reading ("empty means everybody") turns a missing variable into an open door.
    allowed_users: frozenset[str] = frozenset()
    # Token -> login lookups are cached for this long. Not an optimisation: a
    # GitHub API call per request would spend a 5000/hour budget and add GitHub's
    # latency to the request path.
    github_cache_ttl_s: float = 300.0
    ntfy: NtfyCfg = field(default_factory=NtfyCfg)


def _root_tmpdir() -> str:
    base = os.environ.get("TMPDIR", "/tmp").rstrip("/")
    return f"{base}/rossoctl-keda1"


def load() -> Cfg:
    cfg = Cfg()
    cfg.tmpdir = _root_tmpdir()

    toml_path = pathlib.Path(__file__).parent / "config.toml"
    if toml_path.exists():
        d = tomllib.loads(toml_path.read_text())
        k = d.get("kafka", {})
        cfg.kafka_bootstrap = k.get("bootstrap", cfg.kafka_bootstrap)
        cfg.request_topic   = k.get("request_topic",  cfg.request_topic)
        cfg.response_topic  = k.get("response_topic", cfg.response_topic)
        h = d.get("http", {})
        cfg.http_addr    = h.get("addr", cfg.http_addr)
        cfg.http_workers = int(h.get("workers", cfg.http_workers))
        n = d.get("ntfy", {})
        cfg.ntfy = NtfyCfg(
            enabled=bool(n.get("enabled", cfg.ntfy.enabled)),
            base_url=n.get("base_url", cfg.ntfy.base_url),
            topic=n.get("topic", cfg.ntfy.topic),
            token=n.get("token", cfg.ntfy.token),
            phases=tuple(n.get("phases", cfg.ntfy.phases)),
        )
        cfg.public_base_url = n.get("public_base_url", cfg.public_base_url)
        g = d.get("github", {})
        cfg.github_client_id = g.get("client_id", cfg.github_client_id)
        if g.get("allowed_users"):
            cfg.allowed_users = frozenset(
                str(u).strip().lower() for u in g["allowed_users"] if str(u).strip())

    # env overrides
    e = os.environ.get
    cfg.kafka_bootstrap = e("KAFKA_BOOTSTRAP", cfg.kafka_bootstrap)
    cfg.request_topic   = e("REQUEST_TOPIC",   cfg.request_topic)
    cfg.response_topic  = e("RESPONSE_TOPIC",  cfg.response_topic)
    cfg.http_addr       = e("EB_HTTP_ADDR",    cfg.http_addr)
    cfg.http_workers    = int(e("EB_WORKERS",  str(cfg.http_workers)))
    # EVENT_BRIDGE_PUBLIC_BASE_URL is the externally-reachable URL EventBridge
    # advertises in the HTML view + ntfy Click/Actions. Used VERBATIM — the
    # ntfy publisher does not second-guess whether it's loopback or LAN.
    cfg.public_base_url = e("EVENT_BRIDGE_PUBLIC_BASE_URL", cfg.public_base_url)
    cfg.transcript_max_bytes = int(e("EB_TRANSCRIPT_MAX_BYTES",
                                     str(cfg.transcript_max_bytes)))
    cfg.group_deadline_s = float(e("EB_GROUP_DEADLINE_S", str(cfg.group_deadline_s))) or None
    # `name:token,name2:token2`. Absent or empty leaves auth disabled — same
    # guard shape as NTFY_PHASES below, so an unset var never clobbers a default.
    auth_env = e("EB_AUTH_TOKENS")
    if auth_env:
        cfg.auth_tokens = auth.parse_tokens(auth_env)
    cfg.github_client_id = e("EB_GITHUB_CLIENT_ID", cfg.github_client_id)
    allowed_env = e("EB_ALLOWED_USERS")
    if allowed_env:
        cfg.allowed_users = ghauth.parse_allowed_users(allowed_env)
    cfg.github_cache_ttl_s = float(e("EB_GITHUB_CACHE_TTL_S",
                                     str(cfg.github_cache_ttl_s)))

    cfg.ntfy.enabled  = (e("NTFY_ENABLED", "true" if cfg.ntfy.enabled else "false").lower() == "true")
    cfg.ntfy.base_url = e("NTFY_BASE_URL", cfg.ntfy.base_url)
    cfg.ntfy.topic    = e("NTFY_TOPIC",    cfg.ntfy.topic)
    cfg.ntfy.token    = e("NTFY_TOKEN",    cfg.ntfy.token)
    cfg.ntfy.group_notify_errors = (
        e("NTFY_GROUP_NOTIFY_ERRORS", "true" if cfg.ntfy.group_notify_errors else "false")
        .lower() == "true")
    phases_env = e("NTFY_PHASES")
    if phases_env:
        cfg.ntfy.phases = tuple(p.strip() for p in phases_env.split(",") if p.strip())

    (pathlib.Path(cfg.tmpdir) / "eventbridge").mkdir(parents=True, exist_ok=True)
    return cfg
