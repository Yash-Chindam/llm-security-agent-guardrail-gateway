"""The tool registry and the argument-level safety policy for each tool.

Section 11 of the design specification puts an action broker between the agent
and its tools: an allowlist, strict argument schemas, canonical filesystem
paths and URLs, and parsed SQL restricted to a query class. Section 8.4 adds
user and service authorization. A tool that is not registered here cannot be
proposed at all. There is no shell tool: the only way to run code is
`run_code`, which runs in the ephemeral sandbox and never on the host.
"""

from __future__ import annotations

import ipaddress
import posixpath
from dataclasses import dataclass
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

import sqlglot
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from sqlglot import exp
from sqlglot.errors import SqlglotError

from guardrail_gateway.identity import Role
from guardrail_gateway.models import SideEffect

_RecordId = Annotated[
    str, StringConstraints(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
]
_Scalar = str | int | float | bool | None


class _Arguments(BaseModel):
    # Strict and closed: an unexpected field or a coerced type is how extra
    # behaviour is smuggled through a tool call.
    model_config = ConfigDict(extra="forbid", strict=True)


class SearchDocumentsArguments(_Arguments):
    q: str = Field(min_length=1, max_length=500)
    limit: int | None = Field(default=None, ge=1, le=100)


class ExecuteSqlArguments(_Arguments):
    query: str = Field(min_length=1, max_length=10_000)
    limit: int | None = Field(default=None, ge=1, le=10_000)


class SendEmailArguments(_Arguments):
    to: str = Field(max_length=320, pattern=r"^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$")
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(min_length=1, max_length=20_000)


class UpdateRecordArguments(_Arguments):
    record_id: _RecordId
    changes: dict[str, _Scalar] = Field(default_factory=dict, max_length=50)


class DeleteRecordArguments(_Arguments):
    record_id: _RecordId


class ReadFileArguments(_Arguments):
    path: str = Field(min_length=1, max_length=1024)


class FetchUrlArguments(_Arguments):
    url: str = Field(min_length=1, max_length=2048)
    method: Literal["GET"] = "GET"


class RunCodeArguments(_Arguments):
    language: Literal["python"]
    code: str = Field(min_length=1, max_length=20_000)
    # Asking for network access makes the run an external side effect, which
    # needs a reviewer's approval of this exact code.
    network: bool = False


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """What a registered tool may do and who may propose it."""

    effects: frozenset[SideEffect]
    arguments: type[_Arguments]
    roles: frozenset[Role]


_READERS = frozenset({Role.CALLER, Role.OPERATOR})
_OPERATORS = frozenset({Role.OPERATOR})

TOOLS: dict[str, ToolSpec] = {
    "search_documents": ToolSpec(
        frozenset({SideEffect.NONE, SideEffect.READ}), SearchDocumentsArguments, _READERS
    ),
    "execute_sql": ToolSpec(frozenset({SideEffect.READ}), ExecuteSqlArguments, _READERS),
    "read_file": ToolSpec(frozenset({SideEffect.READ}), ReadFileArguments, _READERS),
    "send_email": ToolSpec(frozenset({SideEffect.EXTERNAL}), SendEmailArguments, _OPERATORS),
    "fetch_url": ToolSpec(frozenset({SideEffect.EXTERNAL}), FetchUrlArguments, _OPERATORS),
    "update_record": ToolSpec(frozenset({SideEffect.WRITE}), UpdateRecordArguments, _OPERATORS),
    "delete_record": ToolSpec(
        frozenset({SideEffect.DESTRUCTIVE}), DeleteRecordArguments, _OPERATORS
    ),
    "run_code": ToolSpec(
        frozenset({SideEffect.NONE, SideEffect.EXTERNAL}), RunCodeArguments, _OPERATORS
    ),
}

CODE_TOOL = "run_code"


@dataclass(frozen=True, slots=True)
class ActionPolicyConfig:
    """Deployment-specific limits for the argument-level policies."""

    # Hosts an agent may reach. Empty means no outbound request is permitted.
    allowed_url_hosts: frozenset[str] = frozenset()
    # The only directory tree a file tool may read, relative to the sandbox.
    file_root: str = "workspace"


def validate_arguments(spec: ToolSpec, arguments: dict[str, object]) -> _Arguments | None:
    """Return the parsed arguments, or None when they do not fit the schema."""

    try:
        return spec.arguments.model_validate(arguments)
    except ValidationError:
        return None


# Statement kinds that change data, schema, or session state. A SELECT can
# carry one inside a common table expression, so the whole tree is searched.
_SQL_FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.TruncateTable,
    exp.Copy,
    exp.Command,
    exp.Into,
    exp.Lock,
    exp.Set,
    exp.Transaction,
    exp.Commit,
    exp.Rollback,
    exp.Grant,
)


def sql_violation(query: str) -> str | None:
    """Return a reason code when a query is not a single read-only SELECT.

    The query is parsed rather than pattern-matched, so a keyword inside a
    string literal or a comment is not mistaken for a statement and a
    data-modifying statement cannot hide behind a leading SELECT.
    """

    try:
        statements = sqlglot.parse(query, read="postgres")
    except SqlglotError:
        return "invalid_sql_arguments"

    if len(statements) != 1 or statements[0] is None:
        return "invalid_sql_arguments" if not any(statements) else "sql_not_read_only"

    statement = statements[0]
    if not isinstance(statement, exp.Select | exp.SetOperation):
        return "sql_not_read_only"
    if any(statement.find_all(*_SQL_FORBIDDEN_NODES)):
        return "sql_not_read_only"
    # A function the parser does not recognise is refused rather than trusted:
    # that is where file access, sleeps, and remote connections live.
    if any(statement.find_all(exp.Anonymous)):
        return "sql_function_not_allowed"
    return None


def path_violation(path: str, config: ActionPolicyConfig) -> str | None:
    """Return a reason code unless the path stays inside the workspace root."""

    # An encoded separator or dot has no legitimate use and is how a traversal
    # is carried past a check that runs before decoding.
    if unquote(path) != path or "\x00" in path or "\\" in path:
        return "path_outside_workspace"
    if path.startswith(("/", "~")) or ":" in path:
        return "path_outside_workspace"

    canonical = posixpath.normpath(path)
    if canonical != config.file_root and not canonical.startswith(f"{config.file_root}/"):
        return "path_outside_workspace"
    return None


def url_violation(url: str, config: ActionPolicyConfig) -> str | None:
    """Return a reason code unless the URL is HTTPS to an allowlisted host."""

    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return "url_not_permitted"

    if parts.scheme != "https" or parts.username is not None or parts.password is not None:
        return "url_not_permitted"
    if port not in (None, 443):
        return "url_not_permitted"

    host = (parts.hostname or "").rstrip(".").lower()
    if not host or _is_ip_literal(host):
        # An address literal bypasses name-based allowlisting and is how
        # loopback, link-local metadata, and private ranges are reached.
        return "url_not_permitted"
    if host not in config.allowed_url_hosts:
        return "url_host_not_allowlisted"
    return None


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
