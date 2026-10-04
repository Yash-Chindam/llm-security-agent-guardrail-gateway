# Action policy for the tool enforcement point (design specification,
# sections 8.4, 9, and 11).
#
# The tool registry is data (data.guardrail.tools), generated from the
# gateway's own registry. The gateway parses arguments, SQL, paths, and URLs
# and reports what it found in input.facts; this policy decides what that
# means. It receives a digest of the arguments, never the arguments.
#
# The rules are tried in order and the first that applies decides. Anything
# the rules do not recognise is denied.
package guardrail.action

import rego.v1

default decision := {"verdict": "deny", "reason_code": "policy_default_deny"}

decision := deny("tool_not_allowlisted") if {
	not tool
} else := deny("tool_not_authorized_for_role") if {
	count({role | some role in input.roles} & {role | some role in tool.roles}) == 0
} else := deny("side_effect_mismatch") if {
	not input.side_effect in tool.effects
} else := deny("resource_tenant_mismatch") if {
	not startswith(input.resource, sprintf("tenant:%s:", [input.tenant_id]))
} else := deny(input.facts.argument_violation) if {
	is_string(input.facts.argument_violation)
} else := {"verdict": "require_approval", "reason_code": "risky_action_requires_approval"} if {
	input.side_effect in data.guardrail.approval_effects
	arguments_checked
} else := {"verdict": "allow", "reason_code": "action_policy_allow"} if {
	arguments_checked
}

deny(reason) := {"verdict": "deny", "reason_code": reason}

tool := data.guardrail.tools[input.tool]

# The gateway must say what it found in the arguments. If that fact is
# missing the action falls through to the default denial.
arguments_checked if input.facts.argument_violation == null
