package policy.aws.lambda.vpc_availability_zone

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	function := account.lambda.functions[_]

	id := vpc_id(function.vpcConfiguration)
	subenet_ids := subnets(function.vpcConfiguration)

	d := shisho.decision.aws.lambda.vpc_availability_zone({
		"allowed": allow_if_excluded(count(subenet_ids) > 1, function),
		"subject": function.metadata.id,
		"payload": shisho.decision.aws.lambda.vpc_availability_zone_payload({"vpc_id": id, "subnet_ids": subenet_ids}),
	})
}

vpc_id(config) := id {
	id := config.vpc.metadata.displayName
} else = ""

subnets(config) := config.subnetIds {
	count(config.subnetIds) > 0
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
