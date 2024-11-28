package policy.aws.rds.instance_vpc

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	id := vpc_id(instance.subnetGroup)

	d := shisho.decision.aws.rds.instance_vpc({
		"allowed": allow_if_excluded(id != "", instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_vpc_payload({"vpc_id": id}),
	})
}

vpc_id(subnet_group) := subnet_group.vpc.metadata.id {
	subnet_group.vpc != null
} else = ""

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
