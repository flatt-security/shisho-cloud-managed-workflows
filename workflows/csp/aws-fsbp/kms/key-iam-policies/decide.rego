package policy.aws.kms.key_iam_policies

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	policy := account.iam.policies[_]

	document := json.unmarshal(policy.defaultVersion.rawDocument)
	statements := kms_related_polcy_statements(document, account.id)
	count(statements) > 0

	d := shisho.decision.aws.kms.key_iam_policies({
		"allowed": allow_if_excluded(is_allowed_actions(statements), policy),
		"subject": policy.metadata.id,
		"payload": shisho.decision.aws.kms.key_iam_policies_payload({
			"allow_policy_statements": statements,
			"groups": policy.entities.groups,
			"roles": policy.entities.roles,
			"users": policy.entities.users,
		}),
	})
}

is_allowed_actions(statements) = false {
	statement := statements[_]
	kms_actions(statement.actions)
} else = true

kms_related_polcy_statements(document, account_id) = x {
	x = [{"resources": resources, "actions": extract_values(statement.Action)} |
		statement := document.Statement[_]
		statement.Effect == "Allow"

		# check whether the policy might influence KMS keys or alias
		resources := extract_values(statement.Resource)
		kms_resources(resources, account_id) == true
	]
} else = []

kms_resources(resources, account_id) {
	resource := resources[_]
	[
		"*",
		sprintf("arn:aws:kms:*:%s:key/*", [account_id]),
		sprintf("arn:aws:kms:*:%s:alias/*", [account_id]),
	][_] == resource
} else = false

kms_actions(actions) {
	action := actions[_]
	action in [
		"*",
		"kms:*",
		"kms:Decrypt",
		"kms:ReEncryptFrom",
		"kms:ReEncrypt*",
	]
} else = false

extract_values(statement_values) = statement_values {
	is_array(statement_values) == true
} else = [statement_values]

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
