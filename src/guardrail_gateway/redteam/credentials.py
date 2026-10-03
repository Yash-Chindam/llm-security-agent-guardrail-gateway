"""Mint the credential set the adversarial suite presents to the gateway.

The suite authenticates exactly like a real caller, so it needs the signing
material of the deployment it targets. That is a property of a test deployment,
not of production: a production run targets a gateway whose tokens come from
the real identity provider, and the operator supplies them instead.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from pydantic import SecretStr

from guardrail_gateway.config import Settings
from guardrail_gateway.identity import Role, issue_token
from guardrail_gateway.redteam.runner import CredentialSet
from guardrail_gateway.redteam.scenarios import (
    FOREIGN_TENANT,
    IDENTITY,
    REVIEWER_IDENTITY,
    TENANT,
)

# A validly shaped credential signed with material the gateway does not trust.
_WRONG_KEY = "red-team-wrong-signing-key-0123456789abcdef"


def build_credentials(settings: Settings) -> CredentialSet:
    """Issue one credential per attacker position in the scenario dataset."""

    expired_at = datetime.now(UTC) - timedelta(hours=1)
    forging_settings = settings.model_copy(update={"jwt_secret": SecretStr(_WRONG_KEY)})

    return CredentialSet(
        caller=issue_token(settings, IDENTITY, TENANT, roles=(Role.CALLER, Role.OPERATOR)),
        read_only=issue_token(settings, IDENTITY, TENANT, roles=(Role.CALLER,)),
        reviewer=issue_token(
            settings, REVIEWER_IDENTITY, TENANT, roles=(Role.CALLER, Role.REVIEWER)
        ),
        # The caller itself holding the reviewer role, to attack separation of duties.
        self_reviewer=issue_token(
            settings, IDENTITY, TENANT, roles=(Role.CALLER, Role.OPERATOR, Role.REVIEWER)
        ),
        foreign_tenant=issue_token(
            settings, "intruder@contoso", FOREIGN_TENANT, roles=(Role.CALLER, Role.REVIEWER)
        ),
        forged=issue_token(forging_settings, IDENTITY, TENANT),
        expired=issue_token(settings, IDENTITY, TENANT, lifetime_seconds=60, issued_at=expired_at),
    )
