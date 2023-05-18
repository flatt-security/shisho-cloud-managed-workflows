package policy.aws.iam.administrative_policy_limitation

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	policy := account.iam.policies[_]

	document := json.unmarshal(policy.defaultVersion.rawDocument)
	is_permissive := has_administrative_statement(document)

	d := shisho.decision.aws.iam.administrative_policy_limitation({
		"allowed": is_permissive == false,
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
