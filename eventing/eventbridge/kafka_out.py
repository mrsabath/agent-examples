"""KafkaProducer wrapper — publishes request CloudEvents to the requests topic."""
from __future__ import annotations

from kafka import KafkaProducer
from shared import ce


class Producer:
    def __init__(self, bootstrap: str, request_topic: str, source_uri: str,
                 response_topic: str | None = None) -> None:
        self._prod = KafkaProducer(bootstrap_servers=bootstrap, acks="all", linger_ms=5)
        self._topic = request_topic
        self._response_topic = response_topic
        self._source = source_uri

    def publish_request(
        self,
        *,
        prompt: str,
        correlationid: str,
        sessionuuid: str,
        mode: str,
        model: str | None = None,
        max_turns: int = 3,
        subject: str = "agent-request",
        groupid: str | None = None,
        submitter: str | None = None,
        submitter_iss: str | None = None,
    ) -> str:
        event = ce.new_event(
            type=ce.TYPE_REQUEST,
            source=self._source,
            subject=subject,
            datacontenttype="application/json",
            correlationid=correlationid,
            sessionuuid=sessionuuid,
            mode=mode,
            data={"prompt": prompt, "model": model, "max_turns": max_turns},
            **({"groupid": groupid} if groupid else {}),
            **({ce.EXT_SUBMITTER: submitter} if submitter else {}),
            **({ce.EXT_SUBMITTER_ISS: submitter_iss} if submitter_iss else {}),
        )
        headers, value = ce.to_kafka_binary(event)
        future = self._prod.send(self._topic, key=correlationid.encode(), value=value, headers=headers)
        future.get(timeout=5)
        return event["id"]

    def publish_group_event(self, *, type_: str, groupid: str,
                            data: dict, subject: str = "group") -> str:
        """Publish a group lifecycle event to the RESPONSES topic (§21.2).

        Not requests: EventRunner consumes that topic and would treat a group event as
        an agent run to execute. Responses is also where EventBridge's own consumer and
        ntfy publisher already listen, so the event gets stored, notified and audited
        with no new plumbing.
        """
        if not self._response_topic:
            raise RuntimeError("Producer has no response_topic; cannot publish group events")
        event = ce.new_event(
            type=type_,
            source=self._source,
            subject=subject,
            datacontenttype="application/json",
            groupid=groupid,
            data=data,
        )
        headers, value = ce.to_kafka_binary(event)
        self._prod.send(self._response_topic, key=groupid.encode(),
                        value=value, headers=headers).get(timeout=5)
        return event["id"]

    def close(self) -> None:
        try:
            self._prod.flush(timeout=2)
        finally:
            self._prod.close(timeout=2)
