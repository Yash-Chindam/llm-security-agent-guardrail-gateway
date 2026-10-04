"""Contract tests keeping the analytics assets in step with what the gateway emits.

The ClickHouse schema, the Grafana dashboard, and the Prometheus alert rules
are not executed by this suite. What is checked is the contract: every field
the gateway publishes has a column, and every metric a panel or rule names is
one the gateway exports.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from guardrail_gateway.audit import AuditSink, InMemoryTransport
from guardrail_gateway.metrics import GatewayMetrics
from guardrail_gateway.models import (
    ApprovalStatus,
    DetectorEvidence,
    EnforcementPoint,
    SecurityDecision,
    Verdict,
)

pytestmark = pytest.mark.unit

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
SCHEMA = (DEPLOY / "clickhouse" / "schema.sql").read_text(encoding="utf-8")
DASHBOARD = json.loads(
    (DEPLOY / "grafana" / "dashboards" / "guardrail-gateway.json").read_text(encoding="utf-8")
)
ALERTS = (DEPLOY / "prometheus" / "alerts.yml").read_text(encoding="utf-8")
_METRIC = re.compile(r"\bguardrail_[a-z_]+")


def _columns(table: str) -> set[str]:
    body = re.search(rf"CREATE TABLE IF NOT EXISTS {re.escape(table)}\s*\((.*?)\n\)", SCHEMA, re.S)
    assert body is not None, table
    return {line.split()[0] for line in body.group(1).strip().splitlines()}


def _decision() -> SecurityDecision:
    return SecurityDecision(
        request_id=uuid4(),
        trace_id=uuid4(),
        enforcement_point=EnforcementPoint.OUTPUT,
        tenant_id="acme",
        policy_version="v1",
        verdict=Verdict.TRANSFORM,
        reason_code="sensitive_content_redacted",
        evidence=[
            DetectorEvidence(
                detector="d",
                version="1",
                category="pii_email",
                score=0.9,
                threshold=0.8,
                redacted_excerpt="contact [MATCH] today",
                explanation="An email address was detected.",
            )
        ],
        latency_ms=1.0,
    )


def _emitted_events() -> list[dict[str, Any]]:
    transport = InMemoryTransport(10)
    sink = AuditSink(10, transport)
    sink.publish(_decision())
    sink.publish_rejection("missing_credential", "/v1/inspect/input")
    sink.publish_operation("pseudonyms_restored", "acme", str(uuid4()), 2)
    return transport.snapshot()


def _exported_metrics() -> set[str]:
    metrics = GatewayMetrics()
    metrics.observe(_decision())
    metrics.observe_detector("DeterministicInspector", 0.001)
    metrics.observe_rejection("missing_credential")
    exposition = metrics.render(lambda: dict.fromkeys(ApprovalStatus, 0), 0, 0, 0).decode()
    return set(_METRIC.findall(exposition))


def _referenced(text: str) -> set[str]:
    return set(_METRIC.findall(text))


def test_every_emitted_field_has_a_column_in_both_tables() -> None:
    emitted = {key for event in _emitted_events() for key in event}

    assert emitted <= _columns("guardrail.security_events_queue")
    assert emitted <= _columns("guardrail.security_events")


def test_the_queue_and_the_store_have_the_same_columns() -> None:
    assert _columns("guardrail.security_events_queue") == _columns("guardrail.security_events")


def test_every_event_carries_an_identifier_a_version_and_a_timestamp() -> None:
    for event in _emitted_events():
        assert event["schema_version"] == 1
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00", event["occurred_at"])
        assert len(event["event_id"]) == 36


def test_no_event_field_can_hold_raw_content() -> None:
    forbidden = {"content", "arguments", "redacted_excerpt", "transformed_content", "identity"}

    assert not forbidden & _columns("guardrail.security_events")
    for event in _emitted_events():
        assert not forbidden & set(event)
        assert "[MATCH]" not in json.dumps(event)


def test_the_schema_reads_the_topic_the_gateway_publishes_to() -> None:
    from guardrail_gateway.config import Settings

    assert f"kafka_topic_list = '{Settings().kafka_topic}'" in SCHEMA


def test_every_dashboard_query_names_an_exported_metric() -> None:
    exported = _exported_metrics()
    expressions = [target["expr"] for panel in DASHBOARD["panels"] for target in panel["targets"]]

    assert expressions
    for expression in expressions:
        referenced = _referenced(expression)
        assert referenced, expression
        assert referenced <= exported, expression


def test_the_dashboard_covers_every_metric_family() -> None:
    queries = " ".join(
        target["expr"] for panel in DASHBOARD["panels"] for target in panel["targets"]
    )
    families = {re.sub(r"_(bucket|count|sum|created)$", "", name) for name in _exported_metrics()}

    for family in families:
        assert family in queries, family


def test_dashboard_panels_have_unique_ids_and_do_not_overlap() -> None:
    panels = DASHBOARD["panels"]
    positions = [(panel["gridPos"]["x"], panel["gridPos"]["y"]) for panel in panels]

    assert len({panel["id"] for panel in panels}) == len(panels)
    assert len(set(positions)) == len(panels)


def test_no_dashboard_query_or_alert_groups_by_tenant_or_identity() -> None:
    text = json.dumps(DASHBOARD) + ALERTS

    assert "tenant" not in text
    assert "identity" not in text


def test_every_alert_rule_names_an_exported_metric() -> None:
    exported = _exported_metrics()
    expressions = re.findall(r"expr:\s*(?:>-\s*\n\s*)?(.+)", ALERTS)

    assert len(expressions) == ALERTS.count("- alert:")
    for expression in expressions:
        referenced = _referenced(expression)
        assert referenced, expression
        assert referenced <= exported, expression
