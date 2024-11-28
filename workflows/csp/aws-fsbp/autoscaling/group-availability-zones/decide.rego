package policy.aws.autoscaling.group_availability_zones

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	d := shisho.decision.aws.autoscaling.group_availability_zones({
		"allowed": allow_if_excluded(count(group.availabilityZones) > 1, group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.group_availability_zones_payload({"availability_zones": group.availabilityZones}),
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
