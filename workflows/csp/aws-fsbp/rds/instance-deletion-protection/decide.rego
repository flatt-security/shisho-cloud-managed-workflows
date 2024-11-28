package policy.aws.rds.instance_deletion_protection

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	allowed = instance.deletionProtection

	d := shisho.decision.aws.rds.instance_deletion_protection({
		"allowed": allow_if_excluded(allowed, instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_deletion_protection_payload({"enabled": allowed}),
	})
}

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
