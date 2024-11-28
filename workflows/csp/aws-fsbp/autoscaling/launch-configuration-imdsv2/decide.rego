package policy.aws.autoscaling.launch_configuration_imdsv2

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	allowed = imdsv2_required_or_no_role_attached(group.launchConfiguration)

	d := shisho.decision.aws.autoscaling.launch_configuration_imdsv2({
		"allowed": allow_if_excluded(allowed, group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.launch_configuration_imdsv2_payload({"imdsv2_enabled": allowed}),
	})
}

imdsv2_required_or_no_role_attached(launchConfiguration) {
	launchConfiguration.metadataOptions.httpTokens == "REQUIRED"
} else {
	launchConfiguration.iamInstanceProfile == null
} else {
	launchConfiguration.iamInstanceProfile == ""
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
