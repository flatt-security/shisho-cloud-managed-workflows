package policy.aws.ebs.volume_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ec2.instances[_]

	volumes := volumes_with_encryption(instance.blockDeviceMappings)

	d := shisho.decision.aws.ebs.volume_encryption({
		"allowed": allow_if_excluded(is_encrypted(volumes), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ebs.volume_encryption_payload({"volumes": volumes}),
	})
}

volumes_with_encryption(devices) = x {
	x := [{
		"id": device.ebs.volume.id,
		"encrypted": device.ebs.volume.encrypted,
	} |
		device := devices[_]
	]
}

is_encrypted(volumes) = false {
	volume := volumes[_]
	volume.encrypted == false
} else = true

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
