"""Kafka adapter for the audit transport.

Section 14 of the design specification publishes security events to Kafka
outside the request path. The producer hands an event to a background sender
and returns, so a decision never waits on a broker. Section 15 still applies:
an event the client cannot queue, or that the broker later refuses, is kept so
the audit sink buffers it instead of losing it.

The client library is an optional dependency (`pip install .[kafka]`). It is
pure Python, so it needs no native library in the runtime image. The adapter
only uses the two producer methods below, so tests drive it with a stand-in
and no broker.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from importlib import import_module
from threading import RLock
from time import monotonic
from typing import Any, Protocol

from guardrail_gateway.audit import TransportUnavailableError
from guardrail_gateway.config import Settings

# How long a send may wait for broker metadata or queue space. Kept short so
# an unreachable broker costs a request milliseconds, not its timeout.
_MAX_BLOCK_MS = 250
# Creating a producer waits on the bootstrap brokers, which takes seconds
# when they are down. After a failed attempt the next one waits this long,
# so an outage delays one request and not every request.
_RECONNECT_SECONDS = 5.0


class DeliveryFuture(Protocol):
    def add_callback(self, callback: Callable[[Any], Any]) -> Any:
        """Run when the broker acknowledges the message."""

    def add_errback(self, errback: Callable[[Any], Any]) -> Any:
        """Run when the message could not be delivered."""


class Producer(Protocol):
    """The part of a kafka-python producer this adapter uses."""

    def send(self, topic: str, value: bytes, key: bytes | None) -> DeliveryFuture:
        """Queue one message or raise if it cannot be queued."""

    def flush(self, timeout: float) -> None:
        """Wait for queued messages or raise when the timeout passes."""


class KafkaTransport:
    """Publish audit events to one topic, keyed by tenant.

    Keying by tenant keeps one tenant's events in one partition, so they are
    read back in the order they were decided.

    The producer is created on first use and again after a failed attempt. A
    broker that is down when the gateway starts is therefore an outage the
    audit sink buffers through, not a reason the gateway cannot start.
    """

    def __init__(
        self,
        connect: Callable[[], Producer],
        topic: str,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._connect = connect
        self._topic = topic
        self._clock = clock
        self._producer: Producer | None = None
        self._reconnect_at = 0.0
        # Events the broker refused after they were queued. They are sent again
        # before anything newer, so a refused event is delayed and never lost.
        self._refused: deque[dict[str, Any]] = deque()
        self._in_flight = 0
        self._delivery_failures = 0
        # Delivery callbacks arrive on the client's sender thread.
        self._lock = RLock()

    @property
    def in_flight(self) -> int:
        """Events queued or refused and not yet acknowledged by the broker."""

        with self._lock:
            return self._in_flight + len(self._refused)

    @property
    def delivery_failures(self) -> int:
        with self._lock:
            return self._delivery_failures

    def send(self, event: dict[str, Any]) -> None:
        with self._lock:
            # Taken as a batch: a refusal reported while retrying joins the
            # queue for the next send instead of being retried in a loop.
            retry = list(self._refused)
            self._refused.clear()
            for position, refused in enumerate(retry):
                try:
                    self._produce(refused)
                except TransportUnavailableError:
                    self._refused.extendleft(reversed(retry[position:]))
                    raise
            self._produce(event)

    def close(self, timeout: float = 5.0) -> int:
        """Flush on shutdown; return how many events were left undelivered."""

        with self._lock:
            producer = self._producer
        if producer is not None:
            # A flush that times out is not an error here: the count returned
            # below is what tells the caller something was left behind.
            with suppress(Exception):
                producer.flush(timeout)
        return self.in_flight

    def _produce(self, event: dict[str, Any]) -> None:
        tenant = event.get("tenant_id")
        try:
            future = self._connected().send(
                self._topic,
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode(),
                tenant.encode() if isinstance(tenant, str) else None,
            )
        except Exception as error:
            # No broker, a full queue, and a client error all mean the same
            # thing to the audit sink: this event was not accepted, so keep it.
            raise TransportUnavailableError from error
        self._in_flight += 1
        future.add_callback(self._acknowledged)
        future.add_errback(self._refuse(event))

    def _connected(self) -> Producer:
        if self._producer is None:
            if self._clock() < self._reconnect_at:
                raise ConnectionError("waiting to reconnect")
            try:
                self._producer = self._connect()
            except Exception:
                self._reconnect_at = self._clock() + _RECONNECT_SECONDS
                raise
        return self._producer

    def _acknowledged(self, _metadata: Any) -> None:
        with self._lock:
            self._in_flight -= 1

    def _refuse(self, event: dict[str, Any]) -> Callable[[Any], None]:
        def refused(_error: Any) -> None:
            with self._lock:
                self._in_flight -= 1
                self._delivery_failures += 1
                self._refused.append(event)

        return refused


def producer_factory(settings: Settings) -> Callable[[], Producer]:
    """How to create an idempotent producer that waits for every replica."""

    try:
        client = import_module("kafka")
    except ImportError as error:
        raise RuntimeError(
            "kafka_bootstrap_servers is set but kafka-python is not installed; "
            "install the 'kafka' extra"
        ) from error
    config: dict[str, Any] = {
        "max_block_ms": _MAX_BLOCK_MS,
        **settings.kafka_client_config,
        "bootstrap_servers": settings.kafka_bootstrap_servers,
        # An audit event is acknowledged only once it is replicated, and a
        # retry can never write it twice. Neither can be configured away.
        "acks": "all",
        "enable_idempotence": True,
    }

    def connect() -> Producer:
        producer: Producer = client.KafkaProducer(**config)
        return producer

    return connect
