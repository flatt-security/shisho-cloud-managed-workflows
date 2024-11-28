package policy.aws.ssm.document_accessibility

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	document := account.ssm.documents[_]

	access_denied := public_accessibility(document.permission) == false

	d := shisho.decision.aws.ssm.document_accessibility({
		"allowed": allow_if_excluded(access_denied, document),
		"subject": document.metadata.id,
		"payload": shisho.decision.aws.ssm.document_accessibility_payload({"public_access_denied": access_denied}),
	})
}

public_accessibility(permission) {
	permission.accountIds[_] == "all"
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
