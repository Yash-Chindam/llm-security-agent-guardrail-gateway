"""One contract for every approval and incident store.

The in-memory and SQL stores must behave identically, so each test runs
against both. The SQL store runs on SQLite everywhere, and on PostgreSQL too
when `GUARDRAIL_TEST_DATABASE_URL` names one, which CI does.
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from guardrail_gateway.approvals import ApprovalRepository, ApprovalStore
from guardrail_gateway.incidents import IncidentRepository, IncidentStore
from guardrail_gateway.models import (
    ApprovalStatus,
    Disposition,
    EnforcementPoint,
    IncidentStatus,
    SecurityDecision,
    Severity,
    Verdict,
)
from guardrail_gateway.stores import (
    Database,
    SqlApprovalStore,
    SqlIncidentStore,
    StoreUnavailableError,
    open_database,
)

pytestmark = pytest.mark.unit

POSTGRES_URL = os.environ.get("GUARDRAIL_TEST_DATABASE_URL")
BACKENDS = ["memory", "sqlite", *(["postgres"] if POSTGRES_URL else [])]
START = datetime(2026, 1, 1, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.now = START

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture(autouse=True)
def _close_databases(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every database a test opened, however it opened it."""

    opened: list[Database] = []
    create = Database.__init__

    def tracked(self: Database, *args: Any, **kwargs: Any) -> None:
        create(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(Database, "__init__", tracked)
    yield
    for database in opened:
        database.close()


@pytest.fixture(params=BACKENDS)
def database(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Database | None]:
    if request.param == "memory":
        yield None
        return
    if request.param == "sqlite":
        yield open_database(f"sqlite:///{tmp_path / 'gateway.db'}")
        return
    assert POSTGRES_URL is not None
    store = open_database(POSTGRES_URL)
    for table in ("approvals", "incidents", "incident_decisions", "incident_traces"):
        store.rows("SELECT 1")  # creates the schema before it is cleared
        store.change(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
    yield store


@pytest.fixture
def approvals(database: Database | None, clock: Clock) -> ApprovalRepository:
    if database is None:
        return ApprovalStore(60, clock=clock)
    return SqlApprovalStore(database, 60, clock=clock)


@pytest.fixture
def incidents(database: Database | None, clock: Clock) -> IncidentRepository:
    if database is None:
        return IncidentStore(100, clock=clock)
    return SqlIncidentStore(database, clock=clock)


def _decision(trace: Any = None) -> SecurityDecision:
    return SecurityDecision(
        request_id=uuid4(),
        trace_id=trace or uuid4(),
        enforcement_point=EnforcementPoint.OUTPUT,
        tenant_id="acme",
        policy_version="v1",
        verdict=Verdict.DENY,
        reason_code="canary_leak_detected",
        latency_ms=1.0,
    )


# ---- approvals


def test_a_created_approval_is_pending_and_can_be_read_back(
    approvals: ApprovalRepository,
) -> None:
    created = approvals.create("digest-a", "acme", "user-1")

    stored = approvals.get(created.approval_id)

    assert stored == created
    assert stored is not None and stored.status is ApprovalStatus.PENDING
    assert stored.expires_at - stored.issued_at == timedelta(seconds=60)
    assert approvals.available()


def test_an_approval_is_bound_to_its_digest_and_tenant(approvals: ApprovalRepository) -> None:
    record = approvals.create("digest-a", "acme", "user-1")
    approvals.approve(record.approval_id, "reviewer-1", "Verified")

    assert not approvals.consume(record.approval_id, "digest-b", "acme")
    assert not approvals.consume(record.approval_id, "digest-a", "other")
    assert approvals.consume(record.approval_id, "digest-a", "acme")


def test_an_approval_is_consumed_once(approvals: ApprovalRepository) -> None:
    record = approvals.create("digest-a", "acme", "user-1")
    approvals.approve(record.approval_id, "reviewer-1", "Verified")

    assert approvals.consume(record.approval_id, "digest-a", "acme")
    assert not approvals.consume(record.approval_id, "digest-a", "acme")
    stored = approvals.get(record.approval_id)
    assert stored is not None and stored.status is ApprovalStatus.CONSUMED


def test_a_pending_approval_cannot_be_consumed(approvals: ApprovalRepository) -> None:
    record = approvals.create("digest-a", "acme", "user-1")

    assert not approvals.consume(record.approval_id, "digest-a", "acme")


def test_adjudication_records_the_reviewer_and_rationale(approvals: ApprovalRepository) -> None:
    record = approvals.create("digest-a", "acme", "user-1")

    approved = approvals.approve(record.approval_id, "reviewer-1", "Verified")

    assert approved is not None
    assert (approved.status, approved.reviewer, approved.rationale) == (
        ApprovalStatus.APPROVED,
        "reviewer-1",
        "Verified",
    )


def test_a_rejection_is_final(approvals: ApprovalRepository) -> None:
    record = approvals.create("digest-a", "acme", "user-1")

    approvals.reject(record.approval_id, "reviewer-1", "Not appropriate")
    overturned = approvals.approve(record.approval_id, "reviewer-2", "Looks fine")

    assert overturned is not None and overturned.status is ApprovalStatus.REJECTED
    assert overturned.reviewer == "reviewer-1"
    assert not approvals.consume(record.approval_id, "digest-a", "acme")


def test_an_approval_expires_whether_or_not_it_was_approved(
    approvals: ApprovalRepository, clock: Clock
) -> None:
    pending = approvals.create("digest-a", "acme", "user-1")
    approved = approvals.create("digest-b", "acme", "user-1")
    approvals.approve(approved.approval_id, "reviewer-1", "Verified")
    clock.advance(60)

    late = approvals.approve(pending.approval_id, "reviewer-1", "Too late")

    assert late is not None and late.status is ApprovalStatus.EXPIRED
    assert late.reviewer is None
    assert not approvals.consume(approved.approval_id, "digest-b", "acme")
    stale = approvals.get(approved.approval_id)
    assert stale is not None and stale.status is ApprovalStatus.EXPIRED


def test_an_unknown_approval_is_missing(approvals: ApprovalRepository) -> None:
    assert approvals.get(uuid4()) is None
    assert approvals.approve(uuid4(), "reviewer-1", "x") is None
    assert approvals.reject(uuid4(), "reviewer-1", "x") is None
    assert not approvals.consume(uuid4(), "digest", "acme")


def test_counts_report_every_status(approvals: ApprovalRepository, clock: Clock) -> None:
    expired = approvals.create("d0", "acme", "user-1")
    clock.advance(30)
    approvals.create("d1", "acme", "user-1")
    approved = approvals.create("d2", "acme", "user-1")
    approvals.approve(approved.approval_id, "reviewer-1", "ok")
    rejected = approvals.create("d3", "acme", "user-1")
    approvals.reject(rejected.approval_id, "reviewer-1", "no")
    consumed = approvals.create("d4", "acme", "user-1")
    approvals.approve(consumed.approval_id, "reviewer-1", "ok")
    approvals.consume(consumed.approval_id, "d4", "acme")
    clock.advance(30)

    assert approvals.get(expired.approval_id) is not None
    assert approvals.counts() == {
        ApprovalStatus.PENDING: 1,
        ApprovalStatus.APPROVED: 1,
        ApprovalStatus.REJECTED: 1,
        ApprovalStatus.CONSUMED: 1,
        ApprovalStatus.EXPIRED: 1,
    }


def test_an_approval_presented_many_times_at_once_is_consumed_exactly_once(
    approvals: ApprovalRepository,
) -> None:
    record = approvals.create("digest-a", "acme", "user-1")
    approvals.approve(record.approval_id, "reviewer-1", "Verified")

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(
            pool.map(lambda _: approvals.consume(record.approval_id, "digest-a", "acme"), range(64))
        )

    assert outcomes.count(True) == 1


# ---- incidents


def test_an_opened_incident_cites_its_decisions_and_traces(
    incidents: IncidentRepository,
) -> None:
    trace = uuid4()
    first, second, other = _decision(trace), _decision(trace), _decision()

    opened = incidents.open(
        "acme", "Suspected leak", Severity.HIGH, "reviewer-1", [first, second, other]
    )

    assert opened.decision_ids == [first.decision_id, second.decision_id, other.decision_id]
    assert opened.trace_ids == [trace, other.trace_id]
    assert (opened.status, opened.disposition) == (IncidentStatus.OPEN, Disposition.UNDETERMINED)
    assert (opened.severity, opened.opened_by) == (Severity.HIGH, "reviewer-1")
    assert incidents.get(opened.incident_id, "acme") == opened
    assert incidents.available()


def test_another_tenants_incident_is_missing(incidents: IncidentRepository) -> None:
    opened = incidents.open("acme", "Suspected leak", Severity.LOW, "reviewer-1", [_decision()])

    assert incidents.get(opened.incident_id, "other") is None
    assert incidents.list("other") == []
    assert incidents.update(opened.incident_id, "other", IncidentStatus.CLOSED, None, None) is None
    unchanged = incidents.get(opened.incident_id, "acme")
    assert unchanged is not None and unchanged.status is IncidentStatus.OPEN


def test_incidents_are_listed_newest_first(incidents: IncidentRepository, clock: Clock) -> None:
    older = incidents.open("acme", "First", Severity.LOW, "reviewer-1", [_decision()])
    clock.advance(1)
    newer = incidents.open("acme", "Second", Severity.LOW, "reviewer-1", [_decision()])

    assert [case.incident_id for case in incidents.list("acme")] == [
        newer.incident_id,
        older.incident_id,
    ]


def test_an_update_changes_only_what_it_names(incidents: IncidentRepository, clock: Clock) -> None:
    opened = incidents.open("acme", "Suspected leak", Severity.LOW, "reviewer-1", [_decision()])
    clock.advance(5)

    incidents.update(opened.incident_id, "acme", IncidentStatus.INVESTIGATING, None, None)
    updated = incidents.update(
        opened.incident_id, "acme", None, Disposition.FALSE_POSITIVE, "Tuned the detector"
    )

    assert updated is not None
    assert updated.status is IncidentStatus.INVESTIGATING
    assert updated.disposition is Disposition.FALSE_POSITIVE
    assert updated.remediation == "Tuned the detector"
    assert updated.updated_at - updated.created_at == timedelta(seconds=5)


def test_an_unknown_incident_is_missing(incidents: IncidentRepository) -> None:
    assert incidents.get(uuid4(), "acme") is None
    assert incidents.update(uuid4(), "acme", IncidentStatus.CLOSED, None, None) is None
    incidents.attach(uuid4(), _decision())


def test_a_decision_is_attached_once(incidents: IncidentRepository, clock: Clock) -> None:
    first = _decision()
    opened = incidents.open("acme", "Canary", Severity.CRITICAL, "gateway", [first])
    clock.advance(2)
    second = _decision(first.trace_id)

    incidents.attach(opened.incident_id, second)
    incidents.attach(opened.incident_id, second)

    stored = incidents.get(opened.incident_id, "acme")
    assert stored is not None
    assert stored.decision_ids == [first.decision_id, second.decision_id]
    assert stored.updated_at - stored.created_at == timedelta(seconds=2)


def test_only_an_open_incident_with_the_same_title_covers_a_trace(
    incidents: IncidentRepository,
) -> None:
    decision = _decision()
    opened = incidents.open("acme", "Canary", Severity.CRITICAL, "gateway", [decision])

    covering = incidents.open_for_trace(decision.trace_id, "acme", "Canary")

    assert covering is not None and covering.incident_id == opened.incident_id
    assert incidents.open_for_trace(decision.trace_id, "acme", "Other title") is None
    assert incidents.open_for_trace(decision.trace_id, "other", "Canary") is None
    assert incidents.open_for_trace(uuid4(), "acme", "Canary") is None

    incidents.update(opened.incident_id, "acme", IncidentStatus.INVESTIGATING, None, None)
    assert incidents.open_for_trace(decision.trace_id, "acme", "Canary") is not None
    incidents.update(opened.incident_id, "acme", IncidentStatus.RESOLVED, None, None)
    assert incidents.open_for_trace(decision.trace_id, "acme", "Canary") is None


def test_the_open_count_excludes_resolved_and_closed_cases(
    incidents: IncidentRepository,
) -> None:
    cases = [
        incidents.open("acme", f"Case {n}", Severity.LOW, "reviewer-1", [_decision()])
        for n in range(4)
    ]
    incidents.update(cases[1].incident_id, "acme", IncidentStatus.INVESTIGATING, None, None)
    incidents.update(cases[2].incident_id, "acme", IncidentStatus.RESOLVED, None, None)
    incidents.update(cases[3].incident_id, "acme", IncidentStatus.CLOSED, None, None)

    assert incidents.open_count() == 2


# ---- behaviour only the SQL stores have


def test_records_survive_a_restart(tmp_path: Path, clock: Clock) -> None:
    url = f"sqlite:///{tmp_path / 'gateway.db'}"
    before = SqlApprovalStore(open_database(url), 60, clock=clock)
    record = before.create("digest-a", "acme", "user-1")
    before.approve(record.approval_id, "reviewer-1", "Verified")
    case = SqlIncidentStore(open_database(url), clock=clock).open(
        "acme", "Suspected leak", Severity.HIGH, "reviewer-1", [_decision()]
    )

    after = SqlApprovalStore(open_database(url), 60, clock=clock)

    assert after.consume(record.approval_id, "digest-a", "acme")
    assert SqlIncidentStore(open_database(url), clock=clock).get(case.incident_id, "acme") == case


def test_two_replicas_sharing_a_database_consume_an_approval_once(
    tmp_path: Path, clock: Clock
) -> None:
    url = f"sqlite:///{tmp_path / 'gateway.db'}"
    replicas = [SqlApprovalStore(open_database(url), 60, clock=clock) for _ in range(2)]
    record = replicas[0].create("digest-a", "acme", "user-1")
    replicas[1].approve(record.approval_id, "reviewer-1", "Verified")

    outcomes = [replica.consume(record.approval_id, "digest-a", "acme") for replica in replicas]

    assert outcomes == [True, False]


@pytest.mark.parametrize("backend", [name for name in BACKENDS if name != "memory"])
def test_replicas_racing_on_their_own_connections_consume_an_approval_once(
    backend: str, tmp_path: Path
) -> None:
    url = POSTGRES_URL if backend == "postgres" else f"sqlite:///{tmp_path / 'gateway.db'}"
    assert url is not None
    replicas = [SqlApprovalStore(open_database(url), 60) for _ in range(8)]
    record = replicas[0].create("digest-a", "acme", "user-1")
    replicas[0].approve(record.approval_id, "reviewer-1", "Verified")
    for replica in replicas:
        assert replica.available()

    # No lock in this process is shared between the replicas: only the
    # database decides which of them changes the row.
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(
            pool.map(
                lambda replica: replica.consume(record.approval_id, "digest-a", "acme"),
                replicas * 4,
            )
        )

    assert outcomes.count(True) == 1


def test_expired_approvals_are_purged_after_the_retention_period(
    tmp_path: Path, clock: Clock
) -> None:
    store = SqlApprovalStore(open_database(f"sqlite:///{tmp_path / 'gateway.db'}"), 60, clock=clock)
    old = store.create("d0", "acme", "user-1")
    clock.advance(3_600)
    recent = store.create("d1", "acme", "user-1")

    assert store.purge(timedelta(minutes=30)) == 1
    assert store.get(old.approval_id) is None
    assert store.get(recent.approval_id) is not None


class BrokenConnection:
    def execute(self, statement: str, parameters: Any = ()) -> Any:
        raise sqlite3.OperationalError("server closed the connection")


def _flaky(tmp_path: Path) -> tuple[Database, Callable[[bool], None]]:
    """A database whose next connection the test can break or restore."""

    state = {"broken": False, "connections": 0}

    def connect() -> Any:
        state["connections"] += 1
        if state["broken"]:
            raise sqlite3.OperationalError("connection refused")
        return sqlite3.connect(
            tmp_path / "gateway.db", isolation_level=None, check_same_thread=False
        )

    def set_broken(broken: bool) -> None:
        state["broken"] = broken

    return Database(connect, (sqlite3.Error,)), set_broken


def test_an_unreachable_database_is_reported_as_unavailable(tmp_path: Path) -> None:
    database, set_broken = _flaky(tmp_path)
    set_broken(True)
    store = SqlApprovalStore(database, 60)

    assert not store.available()
    assert not SqlIncidentStore(database).available()
    with pytest.raises(StoreUnavailableError):
        store.create("digest-a", "acme", "user-1")
    with pytest.raises(StoreUnavailableError):
        store.consume(uuid4(), "digest-a", "acme")


def test_the_store_reconnects_once_the_database_returns(tmp_path: Path) -> None:
    database, set_broken = _flaky(tmp_path)
    store = SqlApprovalStore(database, 60)
    record = store.create("digest-a", "acme", "user-1")
    set_broken(True)
    database._connection = BrokenConnection()

    with pytest.raises(StoreUnavailableError):
        store.get(record.approval_id)
    with pytest.raises(StoreUnavailableError):
        store.get(record.approval_id)

    set_broken(False)

    assert store.get(record.approval_id) == record


def test_closing_releases_the_connection_and_a_later_statement_reconnects(
    tmp_path: Path,
) -> None:
    database = open_database(f"sqlite:///{tmp_path / 'gateway.db'}")
    store = SqlApprovalStore(database, 60)
    record = store.create("digest-a", "acme", "user-1")

    database.close()
    database.close()

    assert store.get(record.approval_id) == record


def test_an_unrecognised_database_url_is_refused() -> None:
    with pytest.raises(ValueError, match="postgresql://"):
        open_database("mysql://db/gateway")


def test_a_missing_postgres_driver_is_a_clear_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    monkeypatch.setitem(sys.modules, "psycopg", None)

    with pytest.raises(RuntimeError, match="'postgres' extra"):
        open_database("postgresql://gateway@db/gateway")


def test_a_postgres_url_uses_the_driver_with_its_own_placeholders(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys
    from types import SimpleNamespace

    statements: list[str] = []
    connections: list[tuple[str, dict[str, Any]]] = []

    class Cursor:
        rowcount = 1

        def fetchall(self) -> list[tuple[int]]:
            return [(1,)]

    class Connection:
        def execute(self, statement: str, parameters: Any = ()) -> Cursor:
            statements.append(statement)
            return Cursor()

        def close(self) -> None:
            return None

    def connect(url: str, **options: Any) -> Connection:
        connections.append((url, options))
        return Connection()

    driver = SimpleNamespace(connect=connect, Error=RuntimeError)
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    url = "postgresql://gateway@db/gateway"

    store = SqlApprovalStore(open_database(url), 60)
    store.consume(uuid4(), "digest-a", "acme")

    assert connections == [(url, {"autocommit": True, "connect_timeout": 5})]
    assert "?" not in statements[-1]
    assert statements[-1].count("%s") == 6
