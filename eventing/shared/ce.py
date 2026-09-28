"""CloudEvent envelope helpers and a tiny binary-mode Kafka binding.

Both components independently derive `sessionuuid = uuid5(NAMESPACE, correlationid)`
so no mapping table is needed on the /continue hot path. See DESIGN_PHASE0.md §2.3.

Binary-mode Kafka binding: attributes ride Kafka headers as `ce_*` bytes,
Kafka value is the raw data payload (JSON-encoded when datacontenttype is
application/json). This is what CloudEvents 1.0 §3.1 (kafka-binding) specifies;
we implement it directly here to avoid coupling to fast-moving cloudevents SDK APIs.
"""
from __future__ import annotations

import datetime as _dt
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable

NAMESPACE = uuid.UUID("6e5f8a90-0000-5000-a000-000000000001")

TYPE_REQUEST  = "dev.rossoctl.agent.request.v1"
TYPE_RESPONSE = "dev.rossoctl.agent.response.v1"

# Phase 1 §21 — agent groups. Both lifecycle events ride the RESPONSES topic, not
# requests: EventRunner consumes requests and would try to execute anything there as
# an agent run, while EventBridge already consumes responses and feeds both the store
# and the ntfy publisher from it.
TYPE_GROUP_STARTED   = "dev.rossoctl.agent.group.started.v1"
TYPE_GROUP_COMPLETED = "dev.rossoctl.agent.group.completed.v1"
GROUP_TYPES = (TYPE_GROUP_STARTED, TYPE_GROUP_COMPLETED)

EXT_CORRELATIONID = "correlationid"
EXT_SESSIONUUID   = "sessionuuid"
EXT_MODE          = "mode"
EXT_SEQUENCE      = "sequence"
EXT_PHASE         = "phase"
EXT_FINAL         = "final"
# Phase 1 §11: the id of the request event that caused this response.
EXT_CAUSATIONID   = "causationid"
# Phase 1 §11: detached JWS over the canonical signed attribute set.
EXT_SIGNATURE     = "signature"
# Phase 1 §21: the batch a correlation belongs to. At most one per correlation.
EXT_GROUPID       = "groupid"
# The authenticated caller that submitted this request, from EB_AUTH_TOKENS.
# Absent when auth is disabled. NOT in signing.SIGNED_ATTRS, so it is unsigned
# and forgeable by anyone with write access to the requests topic — it records
# who EventBridge believes submitted, not cryptographic proof.
EXT_SUBMITTER     = "submitter"
# Who vouched for EXT_SUBMITTER: "github" when the login came from a verified
# GitHub sign-in, absent when it came from a static token. Without this a reader
# cannot tell a real identity from a name an operator typed into an env var.
EXT_SUBMITTER_ISS = "submitter_iss"

CE_HEADER_PREFIX = "ce_"
CORE_ATTRS = {"specversion", "type", "source", "id", "time",
              "subject", "datacontenttype"}


def is_group_event(event) -> bool:
    """True for a group lifecycle event.

    The responses consumer routes on this: group events carry `groupid` but no
    `correlationid`, so handing one to `Store.insert_response` would violate its
    (correlationid, sequence) primary key.
    """
    return event.get("type") in GROUP_TYPES


def session_uuid(correlationid: str) -> str:
    return str(uuid.uuid5(NAMESPACE, correlationid))


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class CloudEvent:
    attrs: dict[str, str]
    data: Any = None

    def __getitem__(self, k: str) -> str: return self.attrs[k]
    def __contains__(self, k: str) -> bool: return k in self.attrs
    def get(self, k: str, default: Any = None) -> Any: return self.attrs.get(k, default)


def new_event(**attrs: Any) -> CloudEvent:
    a = {"specversion": "1.0"}
    a.update({k: (str(v) if v is not None else "") for k, v in attrs.items() if k != "data"})
    a.setdefault("id",   str(uuid.uuid4()))
    a.setdefault("time", now_iso())
    return CloudEvent(attrs=a, data=attrs.get("data"))


def to_kafka_binary(event: CloudEvent) -> tuple[list[tuple[str, bytes]], bytes]:
    """Return (headers, value). Caller supplies the message key."""
    headers: list[tuple[str, bytes]] = []
    for k, v in event.attrs.items():
        if v is None or v == "":
            continue
        headers.append((f"{CE_HEADER_PREFIX}{k}", str(v).encode("utf-8")))
    if event.data is None:
        value = b""
    elif isinstance(event.data, (bytes, bytearray)):
        value = bytes(event.data)
    elif event.attrs.get("datacontenttype", "application/json").startswith("application/json"):
        value = json.dumps(event.data, separators=(",", ":")).encode("utf-8")
    else:
        value = str(event.data).encode("utf-8")
    return headers, value


def from_kafka_binary(headers: Iterable[tuple[str, bytes | None]], value: bytes | None) -> CloudEvent:
    attrs: dict[str, str] = {}
    for k, v in headers or []:
        if not k or not k.startswith(CE_HEADER_PREFIX):
            continue
        name = k[len(CE_HEADER_PREFIX):]
        if v is None:
            continue
        attrs[name] = v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)
    data: Any = None
    if value:
        dct = attrs.get("datacontenttype", "application/json")
        raw = bytes(value) if isinstance(value, (bytes, bytearray)) else value
        if dct.startswith("application/json"):
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                data = raw
        else:
            try:
                data = raw.decode("utf-8")
            except UnicodeDecodeError:
                data = raw
    return CloudEvent(attrs=attrs, data=data)


def envelope_dict(event: CloudEvent) -> dict[str, Any]:
    """Flat dict of attributes + `data` — used for /events JSON responses and SQLite raw_json."""
    out = dict(event.attrs)
    out["data"] = event.data
    return out
