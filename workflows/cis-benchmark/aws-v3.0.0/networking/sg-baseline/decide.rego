package policy.aws.networking.sg_baseline

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]
	g := vpc.securityGroups[_]

	g.name == "default"

	ip_permissions_ingress := ip_permissions(g.ipPermissionsIngress)
	ip_permissions_egress := ip_permissions(g.ipPermissionsEgress)

	d := shisho.decision.aws.networking.sg_baseline({
		"allowed": allow_if_excluded(no_ip_permissions(ip_permissions_ingress, ip_permissions_egress), g),
		"subject": g.metadata.id,
		"payload": shisho.decision.aws.networking.sg_baseline_payload({
			"ip_permissions_ingress": ip_permissions_ingress,
			"ip_permissions_egress": ip_permissions_egress,
		}),
	})
}

no_ip_permissions(ip_permissions_ingress, ip_permissions_egress) {
	count(ip_permissions_ingress) == 0
	count(ip_permissions_egress) == 0
} else = false

ip_permissions(group_ip_permissions) = x {
	x := [{
		"ip_protocol": group_ip_permission.ipProtocol,
		"from_port": group_ip_permission.fromPort,
		"to_port": group_ip_permission.toPort,
	} |
		group_ip_permission = group_ip_permissions[_]
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
