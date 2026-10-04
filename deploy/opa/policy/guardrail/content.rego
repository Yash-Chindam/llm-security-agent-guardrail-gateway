# Content policy for the input, context, and output enforcement points
# (design specification, sections 8.1 to 8.3 and 9).
#
# The gateway sends detector evidence as categories, never content. Detectors
# supply evidence; only this policy turns evidence into a verdict.
#
# The rules are tried in order and the first that applies decides. Anything
# the rules do not recognise is denied.
package guardrail.content

import rego.v1

default decision := {"verdict": "deny", "reason_code": "policy_default_deny"}

decision := deny("cross_tenant_context") if {
	cross_tenant
} else := deny("canary_leak_detected") if {
	# A canary has no legitimate reason to be anywhere.
	"canary" in categories
} else := deny("obfuscated_content_detected") if {
	# An obfuscated match has no position in the original text, so it cannot
	# be redacted; the only sound verdict is denial.
	some item in input.evidence
	item.obfuscated == true
} else := deny("embedded_action_detected") if {
	# A tool call belongs at the action endpoint, where it is authorized.
	"embedded_action" in categories
	input.enforcement_point in {"output", "context"}
} else := deny("prompt_injection_detected") if {
	count(categories & {"prompt_injection", "jailbreak"}) > 0
	untrusted
} else := deny("sensitive_content_denied") if {
	"deny" in governed
} else := deny("sensitive_output_detected") if {
	count(governed) > 0
	input.enforcement_point == "output"
} else := transform("sensitive_content_pseudonymized") if {
	governed == {"pseudonymize"}
} else := transform("sensitive_content_redacted") if {
	count(governed) > 0
} else := {"verdict": "allow", "reason_code": "policy_allow"} if {
	well_formed
}

deny(reason) := {"verdict": "deny", "reason_code": reason}

transform(reason) := {"verdict": "transform", "reason_code": reason}

# An input without the fields below is not something this policy can judge,
# so it falls through to the default denial instead of being allowed.
well_formed if {
	input.enforcement_point in {"input", "context", "output"}
	is_string(input.tenant_id)
	is_array(input.evidence)
}

categories := {item.category | some item in input.evidence}

cross_tenant if {
	input.source_tenant_id != null
	input.source_tenant_id != input.tenant_id
}

untrusted if input.enforcement_point == "context"

untrusted if input.trust_level == "untrusted"

sensitive contains category if {
	some category in categories
	category == "secret"
}

sensitive contains category if {
	some category in categories
	startswith(category, "pii_")
}

# What the tenant's rules do with each sensitive category that was found,
# leaving out the categories it lets through. An unlisted category is redacted.
governed := {action |
	some category in sensitive
	action := object.get(input.entity_actions, category, "redact")
	action != "allow"
}
