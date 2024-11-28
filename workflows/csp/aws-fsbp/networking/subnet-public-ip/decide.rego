package policy.aws.networking.subnet_public_ip

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]

	subnets := subent_with_map_Ppublic_ip_on_launch(vpc.subnets)

	d := shisho.decision.aws.networking.subnet_public_ip({
		"allowed": allow_if_excluded(is_map_public_ip_on_launch(subnets), vpc),
		"subject": vpc.metadata.id,
		"payload": shisho.decision.aws.networking.subnet_public_ip_payload({"subnets": subnets}),
	})
}

is_map_public_ip_on_launch(subnets) = false {
	subnets[_].map_public_ip_on_launch == true
} else = true

subent_with_map_Ppublic_ip_on_launch(subnets) = x {
	x := [{"id": subnet.id, "map_public_ip_on_launch": subnet.mapPublicIpOnLaunch} |
		subnet := subnets[_]
	]
} else = []

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
