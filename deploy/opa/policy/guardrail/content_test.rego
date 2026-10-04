package guardrail.content_test

import rego.v1

import data.guardrail.content

base := {
	"enforcement_point": "input",
	"trust_level": "untrusted",
	"source_tenant_id": null,
	"tenant_id": "acme",
	"evidence": [],
	"entity_actions": {},
}

found(category) := {"category": category, "obfuscated": false}

test_clean_content_is_allowed if {
	content.decision == {"verdict": "allow", "reason_code": "policy_allow"} with input as base
}

test_another_tenants_context_is_denied if {
	content.decision.reason_code == "cross_tenant_context" with input as object.union(base, {"source_tenant_id": "other"})
}

test_a_canary_is_denied_even_when_its_category_is_allowed if {
	content.decision.reason_code == "canary_leak_detected" with input as object.union(base, {
		"evidence": [found("canary")],
		"entity_actions": {"canary": "allow"},
	})
}

test_an_obfuscated_match_is_denied if {
	content.decision.reason_code == "obfuscated_content_detected" with input as object.union(base, {"evidence": [{"category": "pii_email", "obfuscated": true}]})
}

test_an_embedded_action_is_denied_in_output_and_context if {
	every point in {"output", "context"} {
		content.decision.reason_code == "embedded_action_detected" with input as object.union(base, {
			"enforcement_point": point,
			"evidence": [found("embedded_action")],
		})
	}
}

test_an_embedded_action_in_user_input_is_not_a_violation if {
	content.decision.verdict == "allow" with input as object.union(base, {"evidence": [found("embedded_action")]})
}

test_an_injection_from_an_untrusted_source_is_denied if {
	content.decision.reason_code == "prompt_injection_detected" with input as object.union(base, {"evidence": [found("jailbreak")]})
}

test_an_injection_in_context_is_denied_whatever_its_trust_level if {
	content.decision.reason_code == "prompt_injection_detected" with input as object.union(base, {
		"enforcement_point": "context",
		"trust_level": "trusted",
		"evidence": [found("prompt_injection")],
	})
}

test_trusted_input_may_discuss_injection if {
	content.decision.verdict == "allow" with input as object.union(base, {
		"trust_level": "trusted",
		"evidence": [found("prompt_injection")],
	})
}

test_sensitive_input_is_redacted_by_default if {
	content.decision == {"verdict": "transform", "reason_code": "sensitive_content_redacted"} with input as object.union(base, {"evidence": [found("pii_email")]})
}

test_sensitive_output_is_denied if {
	content.decision.reason_code == "sensitive_output_detected" with input as object.union(base, {
		"enforcement_point": "output",
		"evidence": [found("secret")],
	})
}

test_a_category_the_tenant_denies_is_denied if {
	content.decision.reason_code == "sensitive_content_denied" with input as object.union(base, {
		"evidence": [found("pii_email"), found("pii_phone")],
		"entity_actions": {"pii_phone": "deny"},
	})
}

test_a_category_the_tenant_allows_passes if {
	content.decision.verdict == "allow" with input as object.union(base, {
		"enforcement_point": "output",
		"evidence": [found("pii_email")],
		"entity_actions": {"pii_email": "allow"},
	})
}

test_pseudonymization_applies_only_when_every_category_asks_for_it if {
	content.decision.reason_code == "sensitive_content_pseudonymized" with input as object.union(base, {
		"evidence": [found("pii_email")],
		"entity_actions": {"pii_email": "pseudonymize"},
	})
	content.decision.reason_code == "sensitive_content_redacted" with input as object.union(base, {
		"evidence": [found("pii_email"), found("secret")],
		"entity_actions": {"pii_email": "pseudonymize"},
	})
}

test_an_input_the_policy_cannot_read_is_denied if {
	content.decision == {"verdict": "deny", "reason_code": "policy_default_deny"} with input as {}
	content.decision.reason_code == "policy_default_deny" with input as object.union(base, {"enforcement_point": "action"})
}
