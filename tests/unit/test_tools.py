"""Unit tests for the tool registry and argument-level safety policies."""

from __future__ import annotations

import pytest

from guardrail_gateway.identity import Role
from guardrail_gateway.models import ActionInspectionRequest, Verdict
from guardrail_gateway.policy import action_verdict
from guardrail_gateway.tools import (
    TOOLS,
    ActionPolicyConfig,
    path_violation,
    sql_violation,
    url_violation,
)

pytestmark = pytest.mark.unit

CONFIG = ActionPolicyConfig(allowed_url_hosts=frozenset({"api.partner.test"}))
READER = frozenset({Role.CALLER})
OPERATOR = frozenset({Role.CALLER, Role.OPERATOR})


def _request(
    tool: str, arguments: dict[str, object], side_effect: str, resource: str | None = None
) -> ActionInspectionRequest:
    return ActionInspectionRequest.model_validate(
        {
            "identity": "user-1",
            "tenant_id": "acme",
            "tool": tool,
            "resource": resource or "tenant:acme:resource",
            "arguments": arguments,
            "side_effect": side_effect,
        }
    )


@pytest.mark.parametrize(
    "query",
    [
        "SELECT count(*) FROM orders",
        "select id, total from orders where total > 100 order by total desc limit 10",
        "SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id",
        "WITH recent AS (SELECT * FROM orders) SELECT count(*) FROM recent",
        "SELECT id FROM a UNION ALL SELECT id FROM b",
        "SELECT id FROM tickets WHERE note = 'please update or delete me'",
        "SELECT 1 -- drop table customers",
        "SELECT 1;",
    ],
)
def test_read_only_queries_are_permitted(query: str) -> None:
    assert sql_violation(query) is None


@pytest.mark.parametrize(
    "query",
    [
        "DROP TABLE customers",
        "SELECT 1; DROP TABLE customers",
        "WITH gone AS (DELETE FROM orders RETURNING *) SELECT * FROM gone",
        "WITH up AS (UPDATE orders SET total = 0 RETURNING *) SELECT * FROM up",
        "SELECT * INTO backup FROM orders",
        "SELECT * FROM orders FOR UPDATE",
        "INSERT INTO orders VALUES (1)",
        "COPY orders TO '/tmp/orders.csv'",
        "TRUNCATE orders",
        "GRANT ALL ON orders TO public",
        "CREATE TABLE x AS SELECT * FROM orders",
    ],
)
def test_statements_that_change_state_are_refused(query: str) -> None:
    assert sql_violation(query) == "sql_not_read_only"


@pytest.mark.parametrize(
    "query",
    ["SELECT pg_read_file('/etc/passwd')", "SELECT pg_sleep(30)", "SELECT dblink('host=x', 'q')"],
)
def test_unrecognised_server_side_functions_are_refused(query: str) -> None:
    assert sql_violation(query) == "sql_function_not_allowed"


@pytest.mark.parametrize("query", ["SELEC nonsense ((", "   ", ";"])
def test_unparseable_sql_is_refused(query: str) -> None:
    assert sql_violation(query) == "invalid_sql_arguments"


@pytest.mark.parametrize(
    "path",
    ["workspace/report.md", "workspace/a/b/../c.txt", "workspace", "workspace/./notes.txt"],
)
def test_paths_inside_the_workspace_are_permitted(path: str) -> None:
    assert path_violation(path, CONFIG) is None


@pytest.mark.parametrize(
    "path",
    [
        "/etc/passwd",
        "~/.ssh/id_rsa",
        "workspace/../../etc/passwd",
        "../workspace/report.md",
        "workspace/%2e%2e/%2e%2e/secrets",
        "workspace%2f..%2f..%2fetc",
        "workspace\\..\\..\\secrets",
        "C:/Windows/system32/config",
        "workspace/report.md\x00.png",
        "workspace-other/report.md",
        "other/report.md",
    ],
)
def test_paths_that_leave_the_workspace_are_refused(path: str) -> None:
    assert path_violation(path, CONFIG) == "path_outside_workspace"


@pytest.mark.parametrize(
    "url",
    [
        "https://api.partner.test/v1/orders",
        "https://API.Partner.Test/v1",
        "https://api.partner.test:443/v1",
        "https://api.partner.test./v1",
    ],
)
def test_https_to_an_allowlisted_host_is_permitted(url: str) -> None:
    assert url_violation(url, CONFIG) is None


@pytest.mark.parametrize(
    "url",
    [
        "http://api.partner.test/v1",
        "ftp://api.partner.test/file",
        "file:///etc/passwd",
        "https://user:secret@api.partner.test/",
        "https://api.partner.test@attacker.example/",
        "https://api.partner.test:8443/",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/admin",
        "https://[::1]/admin",
        "https://api.partner.test:notaport/",
        "https:///no-host",
    ],
)
def test_urls_that_are_unsafe_in_form_are_refused(url: str) -> None:
    assert url_violation(url, CONFIG) == "url_not_permitted"


@pytest.mark.parametrize(
    "url",
    [
        "https://attacker.example/collect",
        "https://api.partner.test.attacker.example/",
        "https://evil-api.partner.test/",
        "https://2130706433/",
        "https://localhost/admin",
    ],
)
def test_hosts_outside_the_allowlist_are_refused(url: str) -> None:
    assert url_violation(url, CONFIG) == "url_host_not_allowlisted"


def test_no_outbound_request_is_permitted_without_an_allowlist() -> None:
    assert (
        url_violation("https://api.partner.test/", ActionPolicyConfig())
        == "url_host_not_allowlisted"
    )


def test_shell_execution_is_not_a_registered_tool() -> None:
    assert not {"run_shell", "exec", "execute_code"} & set(TOOLS)


def test_a_reader_may_use_read_tools() -> None:
    request = _request("execute_sql", {"query": "SELECT 1"}, "read")

    assert action_verdict(request, READER, CONFIG) == (Verdict.ALLOW, "action_policy_allow")


@pytest.mark.parametrize(
    ("tool", "arguments", "side_effect"),
    [
        ("delete_record", {"record_id": "1"}, "destructive"),
        ("update_record", {"record_id": "1"}, "write"),
        ("send_email", {"to": "a@b.test", "subject": "s", "body": "b"}, "external"),
        ("fetch_url", {"url": "https://api.partner.test/"}, "external"),
    ],
)
def test_a_reader_may_not_propose_a_side_effect(
    tool: str, arguments: dict[str, object], side_effect: str
) -> None:
    verdict = action_verdict(_request(tool, arguments, side_effect), READER, CONFIG)

    assert verdict == (Verdict.DENY, "tool_not_authorized_for_role")


def test_a_caller_with_no_recognised_role_may_use_nothing() -> None:
    request = _request("search_documents", {"q": "refund"}, "read")

    assert action_verdict(request, frozenset(), CONFIG)[1] == "tool_not_authorized_for_role"


def test_the_reviewer_role_alone_does_not_permit_proposing_actions() -> None:
    request = _request("delete_record", {"record_id": "1"}, "destructive")
    reviewer_only = frozenset({Role.REVIEWER})

    assert action_verdict(request, reviewer_only, CONFIG)[1] == "tool_not_authorized_for_role"


def test_an_operator_side_effect_still_requires_approval() -> None:
    request = _request("fetch_url", {"url": "https://api.partner.test/v1"}, "external")

    assert action_verdict(request, OPERATOR, CONFIG)[0] is Verdict.REQUIRE_APPROVAL


@pytest.mark.parametrize(
    ("tool", "arguments", "side_effect"),
    [
        ("update_record", {"record_id": "5", "bypass_validation": True}, "write"),
        ("update_record", {}, "write"),
        ("update_record", {"record_id": 5}, "write"),
        ("update_record", {"record_id": "5; DROP TABLE x"}, "write"),
        ("update_record", {"record_id": "5", "changes": {"nested": {"a": 1}}}, "write"),
        ("send_email", {"to": "a@b.test, c@d.test", "subject": "s", "body": "b"}, "external"),
        ("send_email", {"to": "a@b.test", "subject": "s", "body": "b", "bcc": "x@y.z"}, "external"),
        ("search_documents", {"q": "refund", "limit": 100_000}, "read"),
        ("search_documents", {"q": ""}, "read"),
        ("execute_sql", {"query": 42}, "read"),
        ("fetch_url", {"url": "https://api.partner.test/", "method": "POST"}, "external"),
    ],
)
def test_arguments_outside_the_schema_are_refused(
    tool: str, arguments: dict[str, object], side_effect: str
) -> None:
    verdict = action_verdict(_request(tool, arguments, side_effect), OPERATOR, CONFIG)

    assert verdict == (Verdict.DENY, "invalid_tool_arguments")


@pytest.mark.parametrize(
    ("tool", "arguments", "side_effect", "reason"),
    [
        ("execute_sql", {"query": "DROP TABLE x"}, "read", "sql_not_read_only"),
        ("read_file", {"path": "/etc/passwd"}, "read", "path_outside_workspace"),
        ("fetch_url", {"url": "http://10.0.0.1/"}, "external", "url_not_permitted"),
        ("run_shell", {"cmd": "id"}, "destructive", "tool_not_allowlisted"),
        ("execute_sql", {"query": "SELECT 1"}, "write", "side_effect_mismatch"),
    ],
)
def test_the_action_policy_reports_the_specific_violation(
    tool: str, arguments: dict[str, object], side_effect: str, reason: str
) -> None:
    verdict = action_verdict(_request(tool, arguments, side_effect), OPERATOR, CONFIG)

    assert verdict == (Verdict.DENY, reason)


def test_the_default_policy_limits_permit_no_outbound_host() -> None:
    request = _request("fetch_url", {"url": "https://api.partner.test/"}, "external")

    assert action_verdict(request, OPERATOR)[1] == "url_host_not_allowlisted"
