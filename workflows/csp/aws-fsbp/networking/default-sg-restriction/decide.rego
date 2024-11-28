package policy.aws.networking.default_sg_ip_restriction

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]
	group := vpc.securityGroups[_]

	group.name == "default"
	d := shisho.decision.aws.networking.default_sg_restriction({
		"allowed": allow_if_excluded(is_restricted(group), group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.networking.default_sg_restriction_payload({
			"vpc_id": vpc.id,
			"number_of_ingress_permissions": count(group.ipPermissionsIngress),
			"number_of_egress_permissions": count(group.ipPermissionsEgress),
		}),
	})
}

is_restricted(group) {
	count(group.ipPermissionsIngress) == 0
	count(group.ipPermissionsEgress) == 0
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
