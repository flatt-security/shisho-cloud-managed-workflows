package policy.aws.ec2.instance_imdsv2

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ec2.instances[_]

	d := shisho.decision.aws.ec2.instance_imdsv2({
		"allowed": allow_if_excluded(imdsv2_required_or_no_role_attached(instance), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ec2.instance_imdsv2_payload({"use_of_http_tokens": instance.metadataOptions.httpTokens}),
	})
}

imdsv2_required_or_no_role_attached(instance) {
	instance.metadataOptions.httpTokens == "REQUIRED"
} else {
	instance.iamInstanceProfile == null
} else {
	instance.iamInstanceProfile.role == ""
} else {
	instance.iamInstanceProfile.role == null
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
