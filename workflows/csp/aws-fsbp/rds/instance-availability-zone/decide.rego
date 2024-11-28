package policy.aws.rds.instance_availability_zone

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	allowed = instance.multiAz

	d := shisho.decision.aws.rds.instance_availability_zone({
		"allowed": allow_if_excluded(allowed, instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_availability_zone_payload({"multiple_availability_zones_enabled": allowed}),
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
