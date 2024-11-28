package policy.aws.s3.bucket_account_permission

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	document := json.unmarshal(bucket.policy.rawDocument)
	statements := statements_with_cross_account_bucket_access_state(document, account.id)
	count(statements) > 0

	d := shisho.decision.aws.s3.bucket_account_permission({
		"allowed": allow_if_excluded(is_cross_account_bucket_access_denied(statements), bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_account_permission_payload({"policy_allowed_statements": statements}),
	})
}

is_cross_account_bucket_access_denied(statements) = false {
	statement := statements[_]
	statement.cross_account_bucket_access_denied == false
} else = true

statements_with_cross_account_bucket_access_state(document, account_id) := x {
	x := [{"sid": statement.Sid, "cross_account_bucket_access_denied": cross_account_bucket_access_denied(
		statement.Action,
		statement.Principal,
		account_id,
	)} |
		statement := document.Statement[_]
		statement.Effect == "Allow"
	]
} else = []

cross_account_bucket_access_denied(action, principal, account_id) = false {
	denied_actions(action)

	pa := principal_aws(principal)
	[
		pa == "*",
		pa == ["*"],
		other_account_principal(pa, account_id),
	][_] == true
} else = true

denied_action_values := [
	"s3:deletebucketpolicy", "s3:putbucketacl", "s3:putbucketpolicy",
	"s3:putencryptionconfiguration", "s3:putobjectacl",
]

denied_actions(action) {
	# `Statement.Action` might be a single string or a string array
	[single_action(action), array_actions(action)][_] == true
} else = false

single_action(action) {
	denied_action_values[_] == lower(action)
} else = false

array_actions(actions) {
	action := actions[_]
	denied_action_values[_] == lower(action)
} else = false

other_account_principal(aws_principal, account_id) {
	startswith(aws_principal, "arn:aws:iam::")
	endswith(aws_principal, ":root")
	concat("", ["arn:aws:iam::", account_id, ":root"]) != aws_principal
} else = false

principal_aws(principal) := p {
	p := principal.AWS
} else = ""

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
