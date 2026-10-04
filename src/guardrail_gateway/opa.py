"""Open Policy Agent adapter for the policy decision point.

Section 7 of the design specification selects OPA so that authorization is
separate from the application and its rules are testable on their own. The
policy lives in `deploy/opa/policy` as Rego with its own tests.

The gateway sends OPA what it knows and OPA decides:

- For content: the enforcement point, trust level, tenants, the categories of
  detector evidence, and the tenant's rule for each sensitive category.
- For an action: who is asking, the tool, resource, and side effect, a digest
  of the arguments, and what the gateway's parsers found wrong with them.

Content and arguments are never sent. Parsing SQL, paths, and URLs stays in
the gateway, the way detection does: those are facts, and policy is what is
done about them.

Section 15 fixes the failure behaviour. No answer, a slow answer, an undefined
decision, and a malformed one are all the same condition: the policy decision
point is unavailable, and the caller fails closed.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from guardrail_gateway.config import Settings
from guardrail_gateway.detectors import DECODED_DETECTOR
from guardrail_gateway.identity import Role
from guardrail_gateway.models import (
    ActionInspectionRequest,
    DetectorEvidence,
    EnforcementPoint,
    TrustLevel,
    Verdict,
)
from guardrail_gateway.policy import (
    PolicyEngineUnavailableError,
    action_digest,
    argument_violation,
)
from guardrail_gateway.sensitive import action_resolver
from guardrail_gateway.tools import ActionPolicyConfig

CONTENT_PATH = "/v1/data/guardrail/content/decision"
ACTION_PATH = "/v1/data/guardrail/action/decision"
_REASON_CODE = re.compile(r"[a-z][a-z0-9_]{2,63}")
_CONTENT_VERDICTS = frozenset({Verdict.ALLOW, Verdict.DENY, Verdict.TRANSFORM})
_ACTION_VERDICTS = frozenset({Verdict.ALLOW, Verdict.DENY, Verdict.REQUIRE_APPROVAL})


def tool_registry_data() -> dict[str, Any]:
    """The tool registry as OPA data, so policy and gateway cannot disagree."""

    from guardrail_gateway.policy import APPROVAL_EFFECTS
    from guardrail_gateway.tools import TOOLS

    return {
        "approval_effects": sorted(effect.value for effect in APPROVAL_EFFECTS),
        "tools": {
            name: {
                "effects": sorted(effect.value for effect in spec.effects),
                "roles": sorted(role.value for role in spec.roles),
            }
            for name, spec in sorted(TOOLS.items())
        },
    }


class OpaPolicyEngine:
    """Ask an OPA server for each decision."""

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        if settings.opa_url is None:
            raise ValueError("opa_url is not configured")
        self._settings = settings
        self._client = client or httpx.Client(
            base_url=settings.opa_url, timeout=settings.opa_timeout_seconds
        )
        self._limits = ActionPolicyConfig(
            allowed_url_hosts=frozenset(host.lower() for host in settings.allowed_url_hosts),
            file_root=settings.file_root,
        )

    def available(self) -> bool:
        try:
            return self._client.get("/health").status_code == httpx.codes.OK
        except httpx.HTTPError:
            return False

    def close(self) -> None:
        self._client.close()

    def content_verdict(
        self,
        point: EnforcementPoint,
        trust_level: TrustLevel,
        source_tenant_id: str | None,
        tenant_id: str,
        evidence: list[DetectorEvidence],
    ) -> tuple[Verdict, str]:
        resolve = action_resolver(self._settings, tenant_id)
        categories = sorted({item.category for item in evidence})
        return self._decide(
            CONTENT_PATH,
            {
                "enforcement_point": point.value,
                "trust_level": trust_level.value,
                "source_tenant_id": source_tenant_id,
                "tenant_id": tenant_id,
                "evidence": [
                    {"category": item.category, "obfuscated": item.detector == DECODED_DETECTOR}
                    for item in evidence
                ],
                "entity_actions": {category: resolve(category).value for category in categories},
            },
            _CONTENT_VERDICTS,
        )

    def action_verdict(
        self, request: ActionInspectionRequest, roles: frozenset[Role]
    ) -> tuple[Verdict, str]:
        violation = argument_violation(request, self._limits)
        verdict, reason = self._decide(
            ACTION_PATH,
            {
                "enforcement_point": EnforcementPoint.ACTION.value,
                "identity": request.identity,
                "tenant_id": request.tenant_id,
                "roles": sorted(role.value for role in roles),
                "tool": request.tool,
                "resource": request.resource,
                "side_effect": request.side_effect.value,
                "argument_digest": action_digest(request),
                "facts": {"argument_violation": violation},
            },
            _ACTION_VERDICTS,
        )
        if violation is not None and verdict is not Verdict.DENY:
            # A floor under the policy: arguments the gateway could not parse
            # or found unsafe are never executed, whatever a bundle says. A
            # policy can add restrictions; it cannot remove this one.
            return Verdict.DENY, violation
        return verdict, reason

    def _decide(
        self, path: str, document: dict[str, Any], permitted: frozenset[Verdict]
    ) -> tuple[Verdict, str]:
        try:
            response = self._client.post(path, json={"input": document})
            response.raise_for_status()
            result = response.json()["result"]
            verdict = Verdict(result["verdict"])
            reason = result["reason_code"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
            # An undefined decision has no "result" at all. Treating that as
            # "no objection" would turn a missing policy into an open gate.
            raise PolicyEngineUnavailableError from error
        if (
            verdict not in permitted
            or not isinstance(reason, str)
            or not _REASON_CODE.fullmatch(reason)
        ):
            raise PolicyEngineUnavailableError
        return verdict, reason
