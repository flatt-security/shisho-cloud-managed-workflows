package policy.aws.iam.administrative_policy_limitation

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	policy := account.iam.policies[_]

	document := json.unmarshal(policy.defaultVersion.rawDocument)
	is_permissive := has_administrative_statement(document)

	d := shisho.decision.aws.iam.administrative_policy_limitation({
		"allowed": allow_if_excluded(is_permissive == false, policy),
		"subject": policy.metadata.id,
		"payload": shisho.decision.aws.iam.administrative_policy_limitation_payload({}),
	})
}

has_administrative_statement(document) {
	statement := document.Statement[_]
	statement.Effect == "Allow"
	statement.Action == "*"
	statement.Resource == "*"
} else = false

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
