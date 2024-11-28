package policy.aws.ssm.patch_compliance

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ssm.managedInstances[_]

	compliances := incomplete_compliances(instance.compliances)

	d := shisho.decision.aws.ssm.patch_compliance({
		"allowed": allow_if_excluded(count(compliances) == 0, instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ssm.patch_compliance_payload({"incomplete_patch_compliances": compliances}),
	})
}

incomplete_compliances(compliances) = x {
	x = [{"id": compliance.id, "title": compliance.title} |
		compliance := compliances[_]
		compliance.status == "NON_COMPLIANT"
	]
} else = []

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
