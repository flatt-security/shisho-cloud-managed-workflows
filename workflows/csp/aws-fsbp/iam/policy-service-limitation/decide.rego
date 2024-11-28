package policy.aws.iam.policy_service_limitation

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	policy := account.iam.policies[_]

	document := json.unmarshal(policy.defaultVersion.rawDocument)
	statements := allow_policy_statements(document)

	d := shisho.decision.aws.iam.policy_service_limitation({
		"allowed": allow_if_excluded(is_allowed_all_services(statements), policy),
		"subject": policy.metadata.id,
		"payload": shisho.decision.aws.iam.policy_service_limitation_payload({"allow_policy_statements": statements}),
	})
}

is_allowed_all_services(statements) = false {
	statement := statements[_]
	action := statement.actions[_]
	[
		action == "*",
		endswith(action, ":*"),
	][_] == true
} else = true

allow_policy_statements(document) = x {
	x := [{"actions": extract_actions(statement.Action), "resource": statement.Resource} |
		statement := document.Statement[_]
		statement.Effect == "Allow"
		statement.Resource == "*"
	]
} else = []

extract_actions(statement_action) = statement_action {
	is_array(statement_action) == true
} else = [statement_action]

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
