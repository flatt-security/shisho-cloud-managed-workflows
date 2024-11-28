package policy.aws.ec2.instance_network_interface

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ec2.instances[_]

	d := shisho.decision.aws.ec2.instance_network_interface({
		"allowed": allow_if_excluded(count(instance.networkInterfaces) == 1, instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ec2.instance_network_interface_payload({"network_interface_ids": [interface.id |
			interface := instance.networkInterfaces[_]
		]}),
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
