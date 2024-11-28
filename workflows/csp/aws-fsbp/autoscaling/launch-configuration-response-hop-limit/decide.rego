package policy.aws.autoscaling.launch_configuration_response_hop_limit

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	limit = http_put_response_hop_limit(group.launchConfiguration.metadataOptions)

	d := shisho.decision.aws.autoscaling.launch_configuration_response_hop_limit({
		"allowed": allow_if_excluded(limit <= 1, group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.launch_configuration_response_hop_limit_payload({"http_put_response_hop_limit": limit}),
	})
}

http_put_response_hop_limit(metadata_options) = 1 {
	metadata_options == null
} else = metadata_options.httpPutResponseHopLimit

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
