"""Durable SQL stores for approvals and incident cases.

Section 14 of the design specification keeps approvals and incidents in
PostgreSQL. In memory they are lost on restart and invisible to other
replicas, which matters most for approvals: an approval granted on one replica
must be consumable on another, and consumable exactly once across all of them.

That guarantee comes from the database, not from a lock in this process. An
approval is consumed by a single conditional UPDATE, so of any number of
replicas racing to use one approval, exactly one sees a row change.

The statements are plain SQL that PostgreSQL and SQLite both accept. SQLite
gives a single-node deployment durability with no extra service, and lets the
same contract tests run against both engines. The PostgreSQL driver is an
optional dependency (`pip install .[postgres]`).

Times are stored as epoch milliseconds and compared against the gateway's own
clock, so expiry does not depend on the database server's time zone settings.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Sequence
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from importlib import import_module
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

from guardrail_gateway.models import (
    ApprovalRecord,
    ApprovalStatus,
    Disposition,
    IncidentCase,
    IncidentStatus,
    SecurityDecision,
    Severity,
)

_SQLITE_PREFIX = "sqlite:///"
_POSTGRES_PREFIXES = ("postgresql://", "postgres://")

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS approvals (
        approval_id TEXT PRIMARY KEY,
        action_digest TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        reviewer TEXT,
        rationale TEXT,
        status TEXT NOT NULL,
        issued_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        disposition TEXT NOT NULL,
        remediation TEXT,
        opened_by TEXT NOT NULL,
        created_at BIGINT NOT NULL,
        updated_at BIGINT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS incidents_by_tenant ON incidents (tenant_id, created_at)",
    """
    CREATE TABLE IF NOT EXISTS incident_decisions (
        incident_id TEXT NOT NULL,
        decision_id TEXT NOT NULL,
        added_at BIGINT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (incident_id, decision_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_traces (
        incident_id TEXT NOT NULL,
        trace_id TEXT NOT NULL,
        position INTEGER NOT NULL,
        PRIMARY KEY (incident_id, trace_id)
    )
    """,
    "CREATE INDEX IF NOT EXISTS incident_traces_by_trace ON incident_traces (trace_id)",
)


class StoreUnavailableError(Exception):
    """Raised when the database cannot be reached or refuses a statement."""


def _now() -> datetime:
    return datetime.now(UTC)


def _millis(moment: datetime) -> int:
    return int(moment.timestamp() * 1_000)


def _moment(millis: int) -> datetime:
    return datetime.fromtimestamp(millis / 1_000, UTC)


class Database:
    """One connection, re-established after a failure.

    Statements are written with `?` placeholders and translated for drivers
    that use another style. Each statement commits on its own.
    """

    def __init__(
        self,
        connect: Callable[[], Any],
        errors: tuple[type[Exception], ...],
        placeholder: str = "?",
    ) -> None:
        self._connect = connect
        self._errors = errors
        self._placeholder = placeholder
        self._connection: Any = None
        self._schema_ready = False
        self._lock = RLock()

    def rows(self, statement: str, parameters: Sequence[Any] = ()) -> list[tuple[Any, ...]]:
        with self._lock:
            return [tuple(row) for row in self._execute(statement, parameters).fetchall()]

    def change(self, statement: str, parameters: Sequence[Any] = ()) -> int:
        """Run a write and return how many rows it changed."""

        with self._lock:
            return int(self._execute(statement, parameters).rowcount)

    def available(self) -> bool:
        try:
            self.rows("SELECT 1")
        except StoreUnavailableError:
            return False
        return True

    def close(self) -> None:
        with self._lock:
            connection, self._connection = self._connection, None
            if connection is not None:
                with suppress(*self._errors):
                    connection.close()

    def _execute(self, statement: str, parameters: Sequence[Any]) -> Any:
        try:
            if self._connection is None:
                self._connection = self._connect()
            if not self._schema_ready:
                for definition in _SCHEMA:
                    self._connection.execute(definition)
                self._schema_ready = True
            return self._connection.execute(
                statement.replace("?", self._placeholder), tuple(parameters)
            )
        except self._errors as error:
            # The connection may be broken; the next statement starts a new one.
            self._connection = None
            raise StoreUnavailableError from error


def open_database(url: str) -> Database:
    """Open the database a `GUARDRAIL_DATABASE_URL` names."""

    if url.startswith(_SQLITE_PREFIX):
        path = url.removeprefix(_SQLITE_PREFIX)
        return Database(
            lambda: sqlite3.connect(path, isolation_level=None, check_same_thread=False),
            (sqlite3.Error,),
        )
    if url.startswith(_POSTGRES_PREFIXES):
        try:
            driver: Any = import_module("psycopg")
        except ImportError as error:
            raise RuntimeError(
                "database_url names PostgreSQL but psycopg is not installed; "
                "install the 'postgres' extra"
            ) from error
        return Database(
            lambda: driver.connect(url, autocommit=True, connect_timeout=5),
            (driver.Error,),
            placeholder="%s",
        )
    raise ValueError("database_url must start with postgresql:// or sqlite:///")


class SqlApprovalStore:
    """Approvals that survive a restart and are shared between replicas."""

    def __init__(
        self, database: Database, ttl_seconds: int, clock: Callable[[], datetime] = _now
    ) -> None:
        self._database = database
        self._ttl_seconds = ttl_seconds
        self._clock = clock

    def available(self) -> bool:
        return self._database.available()

    def create(self, digest: str, tenant_id: str, requested_by: str) -> ApprovalRecord:
        issued = _millis(self._clock())
        expires = issued + self._ttl_seconds * 1_000
        approval_id = uuid4()
        self._database.change(
            "INSERT INTO approvals ("
            "approval_id, action_digest, tenant_id, requested_by, reviewer, rationale, "
            "status, issued_at, expires_at) VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?)",
            (
                str(approval_id),
                digest,
                tenant_id,
                requested_by,
                ApprovalStatus.PENDING.value,
                issued,
                expires,
            ),
        )
        return ApprovalRecord(
            approval_id=approval_id,
            action_digest=digest,
            tenant_id=tenant_id,
            requested_by=requested_by,
            issued_at=_moment(issued),
            expires_at=_moment(expires),
        )

    def get(self, approval_id: UUID) -> ApprovalRecord | None:
        rows = self._database.rows(
            "SELECT approval_id, action_digest, tenant_id, requested_by, reviewer, rationale, "
            "status, issued_at, expires_at FROM approvals WHERE approval_id = ?",
            (str(approval_id),),
        )
        if not rows:
            return None
        row = rows[0]
        status = ApprovalStatus(row[6])
        expires_at = _moment(row[8])
        if status in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED) and (
            self._clock() >= expires_at
        ):
            status = ApprovalStatus.EXPIRED
        return ApprovalRecord(
            approval_id=UUID(row[0]),
            action_digest=row[1],
            tenant_id=row[2],
            requested_by=row[3],
            reviewer=row[4],
            rationale=row[5],
            status=status,
            issued_at=_moment(row[7]),
            expires_at=expires_at,
        )

    def approve(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        return self._adjudicate(approval_id, reviewer, rationale, ApprovalStatus.APPROVED)

    def reject(self, approval_id: UUID, reviewer: str, rationale: str) -> ApprovalRecord | None:
        return self._adjudicate(approval_id, reviewer, rationale, ApprovalStatus.REJECTED)

    def consume(self, approval_id: UUID, digest: str, tenant_id: str) -> bool:
        # One conditional UPDATE: of any number of replicas presenting the same
        # approval at once, the database lets exactly one change the row.
        changed = self._database.change(
            "UPDATE approvals SET status = ? "
            "WHERE approval_id = ? AND status = ? AND action_digest = ? "
            "AND tenant_id = ? AND expires_at > ?",
            (
                ApprovalStatus.CONSUMED.value,
                str(approval_id),
                ApprovalStatus.APPROVED.value,
                digest,
                tenant_id,
                _millis(self._clock()),
            ),
        )
        return changed == 1

    def counts(self) -> dict[ApprovalStatus, int]:
        rows = self._database.rows(
            "SELECT CASE WHEN status IN (?, ?) AND expires_at <= ? THEN ? ELSE status END "
            "AS reached, COUNT(*) FROM approvals GROUP BY reached",
            (
                ApprovalStatus.PENDING.value,
                ApprovalStatus.APPROVED.value,
                _millis(self._clock()),
                ApprovalStatus.EXPIRED.value,
            ),
        )
        totals = {ApprovalStatus(status): int(count) for status, count in rows}
        return {status: totals.get(status, 0) for status in ApprovalStatus}

    def purge(self, older_than: timedelta) -> int:
        """Delete approvals that expired longer ago than the retention period."""

        return self._database.change(
            "DELETE FROM approvals WHERE expires_at < ?",
            (_millis(self._clock() - older_than),),
        )

    def _adjudicate(
        self, approval_id: UUID, reviewer: str, rationale: str, outcome: ApprovalStatus
    ) -> ApprovalRecord | None:
        # Conditional on still being pending, so two reviewers deciding at once
        # cannot both win and a rejection cannot be overturned.
        self._database.change(
            "UPDATE approvals SET status = ?, reviewer = ?, rationale = ? "
            "WHERE approval_id = ? AND status = ? AND expires_at > ?",
            (
                outcome.value,
                reviewer,
                rationale,
                str(approval_id),
                ApprovalStatus.PENDING.value,
                _millis(self._clock()),
            ),
        )
        return self.get(approval_id)


class SqlIncidentStore:
    """Incident cases that survive a restart and are shared between replicas."""

    def __init__(self, database: Database, clock: Callable[[], datetime] = _now) -> None:
        self._database = database
        self._clock = clock

    def available(self) -> bool:
        return self._database.available()

    def open(
        self,
        tenant_id: str,
        title: str,
        severity: Severity,
        opened_by: str,
        decisions: list[SecurityDecision],
    ) -> IncidentCase:
        now = _millis(self._clock())
        incident_id = str(uuid4())
        trace_ids = list(dict.fromkeys(decision.trace_id for decision in decisions))
        # Children first: a case becomes visible only once its own row exists,
        # so a reader never sees one without the decisions it cites.
        for position, decision in enumerate(decisions):
            self._attach(incident_id, decision.decision_id, now, position)
        for position, trace_id in enumerate(trace_ids):
            self._database.change(
                "INSERT INTO incident_traces (incident_id, trace_id, position) "
                "VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                (incident_id, str(trace_id), position),
            )
        self._database.change(
            "INSERT INTO incidents ("
            "incident_id, tenant_id, title, severity, status, disposition, remediation, "
            "opened_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)",
            (
                incident_id,
                tenant_id,
                title,
                severity.value,
                IncidentStatus.OPEN.value,
                Disposition.UNDETERMINED.value,
                opened_by,
                now,
                now,
            ),
        )
        incident = self.get(UUID(incident_id), tenant_id)
        if incident is None:  # pragma: no cover - the row was written above
            raise StoreUnavailableError
        return incident

    def open_for_trace(self, trace_id: UUID, tenant_id: str, title: str) -> IncidentCase | None:
        rows = self._database.rows(
            "SELECT i.incident_id FROM incidents i "
            "JOIN incident_traces t ON t.incident_id = i.incident_id "
            "WHERE i.tenant_id = ? AND i.title = ? AND i.status IN (?, ?) AND t.trace_id = ? "
            "ORDER BY i.created_at LIMIT 1",
            (
                tenant_id,
                title,
                IncidentStatus.OPEN.value,
                IncidentStatus.INVESTIGATING.value,
                str(trace_id),
            ),
        )
        return self.get(UUID(rows[0][0]), tenant_id) if rows else None

    def attach(self, incident_id: UUID, decision: SecurityDecision) -> None:
        now = _millis(self._clock())
        if self._attach(str(incident_id), decision.decision_id, now, 0):
            self._database.change(
                "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                (now, str(incident_id)),
            )

    def get(self, incident_id: UUID, tenant_id: str) -> IncidentCase | None:
        rows = self._database.rows(
            "SELECT incident_id, tenant_id, title, severity, status, disposition, remediation, "
            "opened_by, created_at, updated_at FROM incidents "
            "WHERE incident_id = ? AND tenant_id = ?",
            (str(incident_id), tenant_id),
        )
        return self._case(rows[0]) if rows else None

    def list(self, tenant_id: str) -> list[IncidentCase]:
        rows = self._database.rows(
            "SELECT incident_id, tenant_id, title, severity, status, disposition, remediation, "
            "opened_by, created_at, updated_at FROM incidents "
            "WHERE tenant_id = ? ORDER BY created_at DESC, incident_id",
            (tenant_id,),
        )
        return [self._case(row) for row in rows]

    def update(
        self,
        incident_id: UUID,
        tenant_id: str,
        status: IncidentStatus | None,
        disposition: Disposition | None,
        remediation: str | None,
    ) -> IncidentCase | None:
        self._database.change(
            "UPDATE incidents SET status = COALESCE(?, status), "
            "disposition = COALESCE(?, disposition), "
            "remediation = COALESCE(?, remediation), updated_at = ? "
            "WHERE incident_id = ? AND tenant_id = ?",
            (
                status.value if status is not None else None,
                disposition.value if disposition is not None else None,
                remediation,
                _millis(self._clock()),
                str(incident_id),
                tenant_id,
            ),
        )
        return self.get(incident_id, tenant_id)

    def open_count(self) -> int:
        rows = self._database.rows(
            "SELECT COUNT(*) FROM incidents WHERE status IN (?, ?)",
            (IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value),
        )
        return int(rows[0][0])

    def _attach(self, incident_id: str, decision_id: UUID, now: int, position: int) -> bool:
        changed = self._database.change(
            "INSERT INTO incident_decisions (incident_id, decision_id, added_at, position) "
            "VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (incident_id, str(decision_id), now, position),
        )
        return changed == 1

    def _case(self, row: tuple[Any, ...]) -> IncidentCase:
        decisions = self._database.rows(
            "SELECT decision_id FROM incident_decisions WHERE incident_id = ? "
            "ORDER BY added_at, position, decision_id",
            (row[0],),
        )
        traces = self._database.rows(
            "SELECT trace_id FROM incident_traces WHERE incident_id = ? ORDER BY position",
            (row[0],),
        )
        return IncidentCase(
            incident_id=UUID(row[0]),
            tenant_id=row[1],
            title=row[2],
            severity=Severity(row[3]),
            status=IncidentStatus(row[4]),
            disposition=Disposition(row[5]),
            remediation=row[6],
            opened_by=row[7],
            created_at=_moment(row[8]),
            updated_at=_moment(row[9]),
            decision_ids=[UUID(item[0]) for item in decisions],
            trace_ids=[UUID(item[0]) for item in traces],
        )
