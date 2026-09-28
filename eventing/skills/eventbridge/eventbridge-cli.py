#!/usr/bin/env python3
"""Skill helper — drive EventBridge from a Claude Code chat or the shell.

Default output is compact: one `ASSISTANT: <reply>` line per turn plus a
one-line summary at the end. `--verbose` shows every stream-json event with
a short label; `--raw` dumps the full JSON payload.

Stdlib-only — safe to run under `python3` or `uv run python`. No deps.
"""
import argparse
import json
import os
import pathlib
import shlex
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Which EventBridge to talk to. Precedence: --base-url > $EVENTBRIDGE_URL > local.
#
# There are TWO different URLs in this system and confusing them wastes an
# afternoon:
#   EVENTBRIDGE_URL              (here, client side) where THIS CLI sends requests
#   EVENT_BRIDGE_PUBLIC_BASE_URL (on the server)     what EventBridge advertises in
#                                                    HTML links and ntfy actions
# Line-buffer stdout. Python block-buffers (8 KiB) when stdout is a pipe rather than a
# terminal, which is always the case under an agent harness — so a progress line written
# at t=3s can still be sitting in this process's buffer at t=180s, and is lost outright
# if the command is killed at a timeout. That is what "the CLI reported nothing" means:
# not that nothing was printed, but that nothing was flushed.
try:
    sys.stdout.reconfigure(line_buffering=True)
    sys.stderr.reconfigure(line_buffering=True)
except (AttributeError, ValueError):  # a replaced/odd stream — not worth failing over
    pass

DEFAULT_BASE = "http://127.0.0.1:8080"


def _normalize_base(url: str) -> str:
    """Accept a bare hostname as well as a full URL.

    `--base-url eventbridge-kev1.apps.example.com` is what someone actually types
    after copying a Route host out of kubectl, so default it to https rather than
    failing with an unhelpful urllib error.
    """
    url = url.strip().rstrip("/")
    if not url:
        return DEFAULT_BASE
    if "://" not in url:
        url = ("http://" if url.startswith(("127.0.0.1", "localhost")) else "https://") + url
    return url


# Resolution happens once, here, and nowhere else: --base-url (applied in main), else
# $EVENTBRIDGE_URL, else the laptop default. `$EVENTBRIDGE_URL` goes through the same
# normalizer as the flag, because the value someone exports is usually a Route host
# copied out of kubectl — a bare hostname, which urllib rejects outright.
_ENV_BASE = os.environ.get("EVENTBRIDGE_URL", "").strip()
BASE = _normalize_base(_ENV_BASE) if _ENV_BASE else DEFAULT_BASE
# Where BASE came from, so the CLI can always SAY it. An agent that cannot see which
# endpoint was chosen goes looking for one, and the endpoint is not something to
# discover.
BASE_SOURCE = "$EVENTBRIDGE_URL" if _ENV_BASE else "default"


def _add_target_flags(sp):
    """Every subcommand takes --base-url, so the endpoint can be given inline
    rather than depending on an exported variable."""
    sp.add_argument("-b", "--base-url", default=None, metavar="URL",
                    help="EventBridge base URL (default: $EVENTBRIDGE_URL, else "
                         "http://127.0.0.1:8080). A bare hostname is assumed https.")


def _token_path() -> pathlib.Path:
    """Where `login` stores the GitHub token.

    XDG if set, else ~/.config — the same place the rest of a user's CLI state
    lives, so it is findable and deletable without documentation.
    """
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return pathlib.Path(base) / "rossoctl-eventing" / "token"


def _read_token() -> str | None:
    """The stored token, or $EVENTBRIDGE_TOKEN, or None.

    The environment wins: a CI job or a one-off shell should be able to act as a
    different identity without disturbing an interactive login.
    """
    env = os.environ.get("EVENTBRIDGE_TOKEN", "").strip()
    if env:
        return env
    try:
        tok = _token_path().read_text().strip()
        return tok or None
    except OSError:
        return None


def _req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {}
    if body:
        headers["Content-Type"] = "application/json"
    token = _read_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        BASE + path, data=data, method=method, headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        # 401 and 403 are the two an operator will actually hit, and they mean
        # different things. A traceback for either sends someone reading urllib
        # internals instead of fixing their access.
        if e.code in (401, 403):
            try:
                detail = json.loads(e.read() or b"{}").get("error", "")
            except Exception:  # noqa: BLE001
                detail = ""
            if e.code == 401:
                print(f"✗ not signed in{': ' + detail if detail else ''}\n"
                      f"  run:  {sys.argv[0]} login", file=sys.stderr)
            else:
                print(f"✗ signed in, but not authorised"
                      f"{': ' + detail if detail else ''}\n"
                      f"  ask an operator to add you to EB_ALLOWED_USERS",
                      file=sys.stderr)
            raise SystemExit(1) from None
        raise
    except OSError as e:
        # Nothing listening, or the name does not resolve. Say what to change rather
        # than raising a traceback that invites hunting for a server: this tool has no
        # discovery step, only the three sources above.
        _die_unreachable(e)


def _die_unreachable(err) -> None:
    reason = getattr(err, "reason", err)
    print(f"✖ cannot reach EventBridge at {BASE} ({reason})", file=sys.stderr)
    print(f"  endpoint came from: {BASE_SOURCE}", file=sys.stderr)
    if BASE_SOURCE == "default":
        print("  No endpoint was given, so this used the laptop default. Point it at the",
              file=sys.stderr)
        print("  right EventBridge — nothing here discovers one for you:", file=sys.stderr)
        print("      export EVENTBRIDGE_URL=https://<eventbridge-host>   # whole session",
              file=sys.stderr)
        print("      … --base-url https://<eventbridge-host>             # one command",
              file=sys.stderr)
    else:
        print("  Check the URL and that EventBridge is up:", file=sys.stderr)
        print(f"      curl -fsS {BASE}/healthz", file=sys.stderr)
    raise SystemExit(2)


# ---- output formatting ----------------------------------------------------

def _fmt_stats(stats):
    """One-line usage summary. Returns '' when there's nothing worth showing."""
    if not isinstance(stats, dict):
        return ""
    bits = []
    if isinstance(stats.get("duration_ms"), (int, float)):
        bits.append(f"{stats['duration_ms']/1000:.1f}s")
    if isinstance(stats.get("total_cost_usd"), (int, float)) and stats["total_cost_usd"] > 0:
        bits.append(f"${stats['total_cost_usd']:.4f}")
    u = stats.get("usage") or {}
    if isinstance(u, dict) and (u.get("input_tokens") or u.get("output_tokens")):
        bits.append(f"{u.get('input_tokens', 0)}→{u.get('output_tokens', 0)} tokens")
    if stats.get("stop_reason") not in (None, "end_turn"):
        bits.append(f"stop={stats['stop_reason']}")
    return " · ".join(bits)


def _print_event_compact(event, state):
    """Compact per-event print. `state` is a dict {'assistant_printed': bool}
    used to avoid duplicating the assistant text when the final frame echoes it.
    """
    d = event.get("data") if isinstance(event.get("data"), dict) else {}
    role = d.get("role")
    text = d.get("text")

    if role == "assistant" and text:
        state["assistant_printed"] = True
        print(f"ASSISTANT: {text}")
    elif role == "final":
        summary = _fmt_stats(d.get("stats"))
        # If nothing else printed the model reply, fall back to the final text.
        if not state.get("assistant_printed") and text:
            print(f"ASSISTANT: {text}")
            state["assistant_printed"] = True
        print(f"✔ done" + (f" · {summary}" if summary else ""))
    elif role == "error" or event.get("phase") == "error":
        msg = text or json.dumps(d, ensure_ascii=False)[:200]
        print(f"✗ error: {msg}")
    # role == "system" (init/hooks) is intentionally silent in compact mode.


def _print_event_verbose(event, state):
    """Show every event with a short label + text (or a short JSON snippet)."""
    d = event.get("data") if isinstance(event.get("data"), dict) else {}
    role = d.get("role") or event.get("phase", "?")
    text = d.get("text")
    seq = event.get("sequence", 0)
    time_s = (event.get("time") or "")[-13:-5]     # HH:MM:SS.mmm
    if text is None:
        snippet = json.dumps({k: v for k, v in d.items() if k != "raw"}, ensure_ascii=False)[:120]
    else:
        snippet = text.replace("\n", " ")[:200]
    marker = " ★" if event.get("final") else ""
    print(f"[{seq:02d} {time_s} {role:9s}]{marker} {snippet}")


def _print_event_raw(event, state):
    print(json.dumps(event.get("data"), ensure_ascii=False))


_STYLES = {
    "compact": _print_event_compact,
    "verbose": _print_event_verbose,
    "raw":     _print_event_raw,
}


# ---- watch loop -----------------------------------------------------------

def _watch(corr, timeout=90.0, *, style="compact"):
    render = _STYLES[style]
    state = {"assistant_printed": False}
    since = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = _req("GET", f"/v0/agents/{corr}/events?since={since}")
        for e in r["events"]:
            since = max(since, e["sequence"])
            render(e, state)
        if r["final"]:
            return
        time.sleep(1.0)
    print(f"… timeout after {timeout:.0f}s; use `watch {corr}` to reconnect")


# ---- commands -------------------------------------------------------------

def _style_from(args) -> str:
    if getattr(args, "raw", False):     return "raw"
    if getattr(args, "verbose", False): return "verbose"
    return "compact"


def cmd_run(args):
    r = _req("POST", "/v0/agents",
             {"prompt": args.prompt, "max_turns": args.max_turns})
    corr = r["correlationid"]
    # No parentheses around the URL — many terminals auto-linkify the URL
    # AND the trailing ')' as one token, which 404s when clicked.
    print(f"▸ agent {corr} · {BASE}/v0/agents/{corr}")
    if args.watch:
        _watch(corr, args.timeout, style=_style_from(args))


def cmd_runmany(args):
    """Start several agents at once and follow all of them.

    The load-bearing detail is the ORDER: every prompt is POSTed *before* any
    watching starts. That puts N requests on the topic together, so KEDA sees lag N
    and scales the EventRunner Deployment to N pods. Posting-then-watching one at a
    time would let each turn finish before the next was submitted — lag would never
    exceed 1, one pod would serve them all, and the concurrency this command exists
    to demonstrate would never happen.
    """
    labels = args.label or []
    agents = []
    for i, prompt in enumerate(args.prompts):
        label = labels[i] if i < len(labels) else f"agent{i + 1}"
        r = _req("POST", "/v0/agents", {"prompt": prompt, "max_turns": args.max_turns})
        corr = r["correlationid"]
        agents.append({"label": label, "corr": corr, "since": 0, "final": False,
                       "state": {"assistant_printed": False}})
        print(f"▸ {label} {corr} · {BASE}/v0/agents/{corr}")
    print(f"· {len(agents)} agent(s) submitted together — KEDA should scale to "
          f"{len(agents)} pod(s)")
    if not args.watch:
        return

    # One poll loop over all of them, so replies appear as each finishes rather than
    # in submission order. Each line is prefixed with its label, because with
    # several agents in flight unlabelled output is unreadable.
    render = _STYLES[_style_from(args)]
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        if all(a["final"] for a in agents):
            break
        for a in agents:
            if a["final"]:
                continue
            r = _req("GET", f"/v0/agents/{a['corr']}/events?since={a['since']}")
            for e in r["events"]:
                a["since"] = max(a["since"], e["sequence"])
                _render_labelled(render, a["label"], e, a["state"])
            if r["final"]:
                a["final"] = True
        if not all(a["final"] for a in agents):
            time.sleep(1.0)

    done = sum(1 for a in agents if a["final"])
    print(f"✔ {done}/{len(agents)} agent(s) finished")
    for a in agents:
        if not a["final"]:
            print(f"… {a['label']} {a['corr']} still running; "
                  f"`watch {a['corr']}` to reconnect")


def _render_labelled(render, label, event, state):
    """Prefix every line a renderer emits with the agent's label."""
    import io
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = buf
    try:
        render(event, state)
    finally:
        sys.stdout = real
    for line in buf.getvalue().splitlines():
        if line.strip():
            print(f"{label} {line}")


# ---- groups (§21) ---------------------------------------------------------

def _group_line(p):
    """One glanceable line. Counts first, percentage second — "12 of 40" can be turned
    into a decision, "30%" cannot."""
    denom = p.get("denominator") or "?"
    bits = [f"{p.get('terminal', 0)}/{denom} done"]
    if p.get("failed"):
        bits.append(f"{p['failed']} failed")
    if p.get("running"):
        bits.append(f"{p['running']} running")
    if p.get("queued"):
        bits.append(f"{p['queued']} queued")
    bits.append(f"{p.get('elapsed', '—')} elapsed")
    if p.get("eta"):
        bits.append(f"{p['eta']} left")
    if p.get("stall_note"):
        bits.append(p["stall_note"])
    return " · ".join(bits)


def _expand_prompts(args) -> list[str]:
    """Positional prompts, or --template/--count generated ones.

    A batch of 100 *different* prompts is the common case and passing 100 shell-quoted
    arguments is both unwieldy and easy to get wrong, so `--template "Say Hello {n}"
    --count 100` generates them. `{n}` is 1-based (or `--start`); `{i}` is 0-based.
    """
    if args.template:
        if args.prompts:
            raise SystemExit("give either PROMPTs or --template, not both")
        if args.count is None or args.count < 1:
            raise SystemExit("--template needs --count N")
        out = []
        for k in range(args.count):
            n = args.start + k
            try:
                out.append(args.template.format(n=n, i=k))
            except (KeyError, IndexError) as e:
                raise SystemExit(
                    f"--template placeholder not understood ({e}); use {{n}} or {{i}}"
                ) from None
        return out
    if not args.prompts:
        raise SystemExit("give one or more PROMPTs, or --template with --count")
    return list(args.prompts)


def cmd_group_run(args):
    """Submit a batch as ONE group, then follow it.

    One POST rather than N: every member's request is published before anything is
    watched, so lag reaches N and KEDA scales past a single pod. Submitting one at a
    time lets each finish before the next arrives and nothing ever scales.
    """
    prompts = _expand_prompts(args)
    body = {"prompts": prompts, "max_turns": args.max_turns}
    if args.label:
        body["label"] = args.label
    if args.min_success:
        body["min_success"] = args.min_success
    r = _req("POST", "/v0/groups", body)
    gid = r["groupid"]
    n = len(r.get("members") or [])
    # URLs first and unwrapped: these are what a human opens, and a terminal that
    # auto-links a trailing ')' sends them to a 404.
    print(f"▸ group {args.label or gid} {gid} · {BASE}/v0/groups/{gid}")
    print(f"  all groups · {BASE}/v0/groups")
    print(f"· {n} agents submitted together"
          + (f" (from template {args.template!r})" if args.template else ""))
    if prompts:
        print(f"  first: {prompts[0]!r}   last: {prompts[-1]!r}")
    if args.watch:
        _watch_group(gid, args.timeout, interval=args.interval)


def cmd_group_status(args):
    p = _req("GET", f"/v0/groups/{args.groupid}/status")
    print(f"▸ group {p.get('label') or args.groupid} {args.groupid} · "
          f"{BASE}/v0/groups/{args.groupid}")
    print(f"  {_group_line(p)}")
    if p.get("state") and p["state"] != "running":
        print(f"  state: {p['state']}")


def cmd_group_watch(args):
    _watch_group(args.groupid, args.timeout, interval=args.interval)


def _watch_group(gid, timeout, interval=2.0):
    """Poll /status until the group reaches a terminal state.

    Reprints only when the numbers change, so a long batch does not scroll away the
    context around it.
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            p = _req("GET", f"/v0/groups/{gid}/status")
        except Exception as e:  # noqa: BLE001
            print(f"  (status unavailable: {e})")
            time.sleep(interval)
            continue
        line = _group_line(p)
        if line != last:
            print(f"  {line}")
            last = line
        if p.get("completed_utc"):
            reason = p.get("completion_reason") or "all"
            tail = "" if reason == "all" else f" ({reason})"
            print(f"✔ group complete{tail} · {p.get('finished', 0)} finished · "
                  f"{p.get('failed', 0)} failed · {p.get('elapsed')}")
            return
        time.sleep(interval)
    print(f"… still running after {timeout:.0f}s; "
          f"`group status {gid}` or open {BASE}/v0/groups/{gid}")


def cmd_group_list(args):
    r = _req("GET", "/v0/groups")
    rows = r.get("groups") or []
    if not rows:
        print("no groups yet")
        return
    for g in rows:
        state = g.get("completion_reason") or ("running" if not g.get("completed_utc")
                                               else "complete")
        print(f"{g['groupid']}  {state:<9} expected={g.get('expected') or '?':<5} "
              f"{g.get('label') or ''}")


def cmd_watch(args):
    _watch(args.correlationid, args.timeout, style=_style_from(args))


def cmd_cont(args):
    r = _req("POST", f"/v0/agents/{args.correlationid}/continue",
             {"prompt": args.prompt})
    print(f"▸ resumed {r['correlationid']}  (turn hint seq={r.get('sequence')})")
    _watch(args.correlationid, args.timeout, style=_style_from(args))


def cmd_selftest(args):
    path = "/v0/selftest"
    if args.url:
        qs = "&".join(f"url={urllib.parse.quote(u, safe='')}" for u in args.url)
        path = f"/v0/selftest?{qs}"
    r = _req("GET", path)
    print(f"[selftest] EventBridge is bound to {r.get('http_addr', '?')}")
    print(f"[selftest] EVENT_BRIDGE_PUBLIC_BASE_URL={r.get('current_public_base_url', '?')}")
    marker = {"recommended": "✔", "reachable-same-host-only": "•",
              "reachable-lan-only": "◐", "reachable-vpn-only": "◐",
              "not-listening": "✗", "unknown": "?"}
    for c in r.get("candidates", []):
        m = marker.get(c["verdict"], "?")
        print(f"  {m} {c['url']:<40}  [{c['verdict']}]  iface={c.get('interface','?')}")
        for note in c.get("notes", []):
            print(f"      · {note}")


# ---- sign-in ----------------------------------------------------------------

# The OAuth App client id is PUBLIC: the device flow has no client secret, which
# is why this can be a default in source. Override for a different app.
DEFAULT_GITHUB_CLIENT_ID = "Ov23liA2Z4jfbFRoJKZn"


def cmd_login(args):
    """GitHub device flow: print a code, wait for the browser, store the token.

    Deliberately prints the code and the URL and then blocks. The alternative —
    opening a browser automatically — fails silently over SSH and in a container,
    which is where this is most often run.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
    from eventbridge import ghauth

    client_id = args.client_id or os.environ.get(
        "EB_GITHUB_CLIENT_ID") or DEFAULT_GITHUB_CLIENT_ID
    try:
        start = ghauth.start_device_flow(client_id)
    except RuntimeError as e:
        print(f"✗ {e}", file=sys.stderr)
        raise SystemExit(1) from None

    print(f"\n  Open {start.get('verification_uri', ghauth.VERIFICATION_URL)}")
    print(f"  Enter code: {start['user_code']}\n")
    print("  Waiting for you to authorise in the browser (Ctrl-C to abort)...")

    try:
        token = ghauth.poll_for_token(
            client_id, start["device_code"],
            interval=start.get("interval"),
            expires_in=float(start.get("expires_in", 900)))
    except KeyboardInterrupt:
        print("\n✗ aborted", file=sys.stderr)
        raise SystemExit(130) from None
    except (RuntimeError, TimeoutError) as e:
        print(f"✗ {e}", file=sys.stderr)
        raise SystemExit(1) from None

    login, err = ghauth.fetch_login(token)
    if login is None:
        print(f"✗ signed in, but could not read the account: {err}", file=sys.stderr)
        raise SystemExit(1) from None

    dest = _token_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(token)
    dest.chmod(0o600)          # a token is a credential; not world-readable
    print(f"✔ signed in as {login}")
    print(f"  token stored at {dest} (mode 600)")


def cmd_logout(args):
    """Forget the stored token. Does not revoke it on GitHub."""
    dest = _token_path()
    try:
        dest.unlink()
        print(f"✔ removed {dest}")
    except FileNotFoundError:
        print("• no stored token")
    print("  to revoke access entirely: https://github.com/settings/applications")


def cmd_whoami(args):
    """Who the stored token belongs to, asked of GitHub rather than assumed."""
    token = _read_token()
    if not token:
        print("• not signed in", file=sys.stderr)
        raise SystemExit(1)
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
    from eventbridge import ghauth
    login, err = ghauth.fetch_login(token)
    if login is None:
        print(f"✗ {err}", file=sys.stderr)
        raise SystemExit(1)
    src = "$EVENTBRIDGE_TOKEN" if os.environ.get("EVENTBRIDGE_TOKEN") else str(_token_path())
    print(f"✔ {login}  (token from {src})")


def cmd_chat(args):
    r = _req("GET", f"/v0/agents/{args.correlationid}/turns")
    print(f"correlationid: {r['correlationid']}  {len(r['turns'])} turns  final={r['final']}")
    for t in r["turns"]:
        stats = _fmt_stats(t.get("stats"))
        head = f"— Turn {t['turn_index']} ({t.get('mode') or '?'}"
        if stats: head += ", " + stats
        head += ") —"
        print()
        print(head)
        print(f"USER:      {t.get('prompt') or '(not recorded)'}")
        ans = t.get("assistant_text")
        print(f"ASSISTANT: {ans if ans else '(no text)'}")


def _add_style_flags(sub):
    sub.add_argument("-v", "--verbose", action="store_true",
                     help="show every event (system/init, assistant, final) with a short label")
    sub.add_argument("--raw", action="store_true",
                     help="dump each event's data as JSON (debug only)")


ECHO_ENV = "EVENTBRIDGE_ECHO"


def _echo_command(argv=None) -> None:
    """Print the exact command being run, in copy-pasteable form.

    An agent driving this CLI describes what it is about to do in prose, and prose is
    not reproducible: the reader cannot tell `--count 100` from `--count 10`, or see
    which endpoint was really used. Echoing argv makes every transcript replayable by
    hand, and makes a wrong flag visible at the moment it is used rather than in the
    results. Set EVENTBRIDGE_ECHO=0 to suppress.
    """
    if os.environ.get(ECHO_ENV, "1").strip().lower() in ("0", "false", "no", "off"):
        return
    argv = list(sys.argv if argv is None else argv)
    script, rest = argv[0], argv[1:]
    # Credentials never arrive as arguments today, but a base URL is free-form and
    # could carry userinfo — echoing it would put it in the transcript verbatim.
    rest = [_redact_userinfo(a) for a in rest]
    parts = ["python3", script, *rest]
    print("$ " + " ".join(shlex.quote(x) for x in parts))


def _redact_userinfo(arg: str) -> str:
    if "@" not in arg or "//" not in arg:
        return arg
    head, sep, tail = arg.partition("//")
    userinfo, at, host = tail.partition("@")
    if not at or "/" in userinfo:
        return arg
    return f"{head}{sep}***@{host}"


def main():
    p = argparse.ArgumentParser(
        description="Drive EventBridge — run/continue/watch/chat with a Claude agent.",
    )
    sub = p.add_subparsers(dest="op", required=True)

    li = sub.add_parser("login", help="sign in with GitHub (device flow)")
    li.add_argument("--client-id", default=None, metavar="ID",
                    help="OAuth App client id (default: $EB_GITHUB_CLIENT_ID, "
                         "else the built-in demo app)")
    li.set_defaults(fn=cmd_login)

    lo = sub.add_parser("logout", help="forget the stored token")
    lo.set_defaults(fn=cmd_logout)

    wai = sub.add_parser("whoami", help="show who the stored token belongs to")
    wai.set_defaults(fn=cmd_whoami)

    r = sub.add_parser("run", help="start an agent with a prompt and print its reply")
    r.add_argument("prompt")
    r.add_argument("--max-turns", type=int, default=3)
    r.add_argument("--watch", action=argparse.BooleanOptionalAction, default=True,
                   help="stream the reply inline (default). --no-watch returns immediately.")
    r.add_argument("--timeout", type=float, default=120.0)
    _add_style_flags(r)
    _add_target_flags(r)
    r.set_defaults(fn=cmd_run)

    rm = sub.add_parser("runmany",
                        help="start several agents AT ONCE and follow them all "
                             "(this is what makes KEDA scale past one pod)")
    rm.add_argument("prompts", nargs="+", metavar="PROMPT")
    rm.add_argument("--label", action="append", default=[], metavar="NAME",
                    help="name for each agent, in order (default agent1, agent2, …)")
    rm.add_argument("--max-turns", type=int, default=3)
    rm.add_argument("--watch", action=argparse.BooleanOptionalAction, default=True)
    rm.add_argument("--timeout", type=float, default=180.0)
    _add_style_flags(rm)
    _add_target_flags(rm)
    rm.set_defaults(fn=cmd_runmany)

    w = sub.add_parser("watch", help="poll an existing correlationid until it finishes")
    w.add_argument("correlationid")
    w.add_argument("--timeout", type=float, default=120.0)
    _add_style_flags(w)
    _add_target_flags(w)
    w.set_defaults(fn=cmd_watch)

    c = sub.add_parser("cont", help="send another prompt to an existing correlationid (resumes claude session)")
    c.add_argument("correlationid")
    c.add_argument("prompt")
    c.add_argument("--timeout", type=float, default=120.0)
    _add_style_flags(c)
    _add_target_flags(c)
    c.set_defaults(fn=cmd_cont)

    ch = sub.add_parser("chat", help="show turn-grouped USER/ASSISTANT view")
    ch.add_argument("correlationid")
    _add_target_flags(ch)
    ch.set_defaults(fn=cmd_chat)

    gp = sub.add_parser("group", help="run and track a GROUP of agents (§21)")
    gsub = gp.add_subparsers(dest="group_op", required=True)

    grun = gsub.add_parser("run", help="submit N prompts as one group and follow it")
    grun.add_argument("prompts", nargs="*", metavar="PROMPT")
    grun.add_argument("--template", default=None, metavar="TEXT",
                      help='generate prompts, e.g. --template "Say Hello {n}" --count 100. '
                           "{n} is 1-based, {i} is 0-based.")
    grun.add_argument("--count", type=int, default=None,
                      help="how many prompts --template should generate")
    grun.add_argument("--start", type=int, default=1,
                      help="first value of {n} (default 1)")
    grun.add_argument("--label", default=None)
    grun.add_argument("--max-turns", type=int, default=3)
    grun.add_argument("--min-success", type=int, default=None,
                      help="complete as soon as this many members succeed")
    grun.add_argument("--watch", action=argparse.BooleanOptionalAction, default=True)
    grun.add_argument("--timeout", type=float, default=900.0)
    grun.add_argument("--interval", type=float, default=2.0)
    _add_target_flags(grun)
    grun.set_defaults(fn=cmd_group_run)

    gst = gsub.add_parser("status", help="one-shot progress for a group")
    gst.add_argument("groupid")
    _add_target_flags(gst)
    gst.set_defaults(fn=cmd_group_status)

    gw = gsub.add_parser("watch", help="follow a group to completion")
    gw.add_argument("groupid")
    gw.add_argument("--timeout", type=float, default=900.0)
    gw.add_argument("--interval", type=float, default=2.0)
    _add_target_flags(gw)
    gw.set_defaults(fn=cmd_group_watch)

    gl = gsub.add_parser("list", help="recent groups")
    _add_target_flags(gl)
    gl.set_defaults(fn=cmd_group_list)

    st = sub.add_parser("selftest", help="diagnose which EVENT_BRIDGE_PUBLIC_BASE_URL a phone could reach")
    st.add_argument("--url", action="append", default=[],
                    help="extra URL to probe (repeatable); useful for verifying a fresh ngrok/cloudflared URL")
    _add_target_flags(st)
    st.set_defaults(fn=cmd_selftest)

    args = p.parse_args()

    # Resolve the endpoint before dispatch, and SAY which one when it is not the
    # local default. Silently talking to localhost when you meant a cluster is the
    # single most confusing way for this to fail.
    global BASE, BASE_SOURCE
    if getattr(args, "base_url", None):
        BASE = _normalize_base(args.base_url)
        BASE_SOURCE = "--base-url"
    _echo_command()
    # Always, including the default. Printing only the interesting case is what let a
    # run quietly go to localhost and look like "the agent never replied".
    print(f"· endpoint {BASE} (from {BASE_SOURCE})")
    args.fn(args)


if __name__ == "__main__":
    main()
