package policy.aws.ec2.instance_vpc_endpoint

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ec2.instances[_]

	endpoints := endpoints_with_service_name(instance.vpc.endpoints)

	d := shisho.decision.aws.ec2.instance_vpc_endpoint({
		"allowed": allow_if_excluded(allowed(endpoints), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ec2.instance_vpc_endpoint_payload({
			"vpc_endpoints": endpoints,
			"vpc_id": instance.vpc.id,
		}),
	})
}

allowed(endpoints) {
	endpoint := endpoints[_]
	endswith(endpoint.service_name, ".ec2")
} else = false

endpoints_with_service_name(endpoints) = x {
	x := [{"id": endpoint.id, "service_name": endpoint.serviceName} |
		endpoint := endpoints[_]
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
