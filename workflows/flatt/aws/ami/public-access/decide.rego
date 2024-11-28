package policy.aws.flatt.ami.public_access

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	image := account.ec2.images[_]

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1",
		"kind": "aws_ami_public_access",
		"subject": image.metadata.id,
		"locator": "",
		"severity": shisho.decision.severity_critical,
		"allowed": allow_if_excluded(image.isPublic == false, image),
		"payload": json.marshal({"is_public": image.isPublic}),
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
