package policy.aws.lambda.public_access

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	function := account.lambda.functions[_]

	document := json.unmarshal(function.policy.rawPolicy)
	statements := statements_with_public_access_state(document)

	d := shisho.decision.aws.lambda.public_access({
		"allowed": allow_if_excluded(is_public_access_denied(statements), function),
		"subject": function.metadata.id,
		"payload": shisho.decision.aws.lambda.public_access_payload({"statements": statements}),
	})
}

is_public_access_denied(statements) = false {
	statement := statements[_]
	statement.public_access_denied == false
} else = true

statements_with_public_access_state(document) := x {
	x := [{"sid": statement.Sid, "public_access_denied": public_access_denied(statement.Principal)} |
		statement := document.Statement[_]
		statement.Effect == "Allow"
	]
} else = []

public_access_denied(principal) {
	principal != "*"
	principal_aws(principal) != "*"
	principal_aws(principal) != ["*"]
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
