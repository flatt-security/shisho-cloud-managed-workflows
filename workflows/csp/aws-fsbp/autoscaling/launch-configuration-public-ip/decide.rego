package policy.aws.autoscaling.launch_configuration_public_ip

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	associated := group.launchConfiguration.associatePublicIpAddress

	d := shisho.decision.aws.autoscaling.launch_configuration_public_ip({
		"allowed": allow_if_excluded(associated == false, group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.launch_configuration_public_ip_payload({"public_ip_address_associated": associated}),
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
