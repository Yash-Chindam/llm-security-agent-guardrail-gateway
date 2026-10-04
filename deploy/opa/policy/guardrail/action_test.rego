package guardrail.action_test

import rego.v1

import data.guardrail.action

base := {
	"enforcement_point": "action",
	"identity": "user-1",
	"tenant_id": "acme",
	"roles": ["caller"],
	"tool": "search_documents",
	"resource": "tenant:acme:kb",
	"side_effect": "read",
	"argument_digest": "0",
	"facts": {"argument_violation": null},
}

write := object.union(base, {
	"roles": ["caller", "operator"],
	"tool": "update_record",
	"resource": "tenant:acme:orders",
	"side_effect": "write",
})

test_a_read_by_a_caller_is_allowed if {
	action.decision == {"verdict": "allow", "reason_code": "action_policy_allow"} with input as base
}

test_an_unregistered_tool_is_denied if {
	action.decision.reason_code == "tool_not_allowlisted" with input as object.union(base, {"tool": "run_shell"})
}

test_a_tool_the_role_may_not_propose_is_denied if {
	action.decision.reason_code == "tool_not_authorized_for_role" with input as object.union(write, {"roles": ["caller"]})
	action.decision.reason_code == "tool_not_authorized_for_role" with input as object.union(base, {"roles": []})
}

test_a_misdeclared_side_effect_is_denied if {
	action.decision.reason_code == "side_effect_mismatch" with input as object.union(write, {"side_effect": "read"})
}

test_another_tenants_resource_is_denied if {
	action.decision.reason_code == "resource_tenant_mismatch" with input as object.union(base, {"resource": "tenant:other:kb"})
}

test_a_resource_that_only_starts_like_the_tenant_is_denied if {
	action.decision.reason_code == "resource_tenant_mismatch" with input as object.union(base, {"resource": "tenant:acme-evil:kb"})
}

test_an_argument_violation_is_denied_with_its_own_reason if {
	action.decision == {"verdict": "deny", "reason_code": "sql_not_read_only"} with input as object.union(base, {"facts": {"argument_violation": "sql_not_read_only"}})
}

test_a_write_requires_approval if {
	action.decision == {"verdict": "require_approval", "reason_code": "risky_action_requires_approval"} with input as write
}

test_every_effect_that_changes_something_requires_approval if {
	every name, spec in data.guardrail.tools {
		every effect in spec.effects {
			request := object.union(base, {
				"roles": spec.roles,
				"tool": name,
				"side_effect": effect,
			})
			expected := {true: "require_approval", false: "allow"}[effect in {"write", "external", "destructive"}]
			action.decision.verdict == expected with input as request
		}
	}
}

test_an_action_without_argument_facts_is_denied if {
	action.decision == {"verdict": "deny", "reason_code": "policy_default_deny"} with input as object.remove(base, ["facts"])
	action.decision.reason_code == "policy_default_deny" with input as object.remove(write, ["facts"])
}

test_an_empty_input_is_denied if {
	action.decision.verdict == "deny" with input as {}
}
