package policy.aws.elb.availability_zones

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	target_type_names := ["AWSELBApplicationLoadBalancer", "AWSELBNetworkLoadBalancer", "AWSELBGatewayLoadBalancer"]
	lb.__typename in target_type_names

	zones := array.concat(alb_zones(lb), array.concat(nlb_zones(lb), glb_zones(lb)))

	d := shisho.decision.aws.elb.availability_zones({
		"allowed": allow_if_excluded(count(zones) > 1, lb),
		"subject": lb.metadata.id,
		"payload": shisho.decision.aws.elb.availability_zones_payload({"zones": zones}),
	})
}

alb_zones(lb) := x {
	x := [zone.name |
		lb.__typename == "AWSELBApplicationLoadBalancer"
		zone := lb.albAvailabilityZones[_]
	]
} else := []

nlb_zones(lb) := x {
	x := [zone.name |
		lb.__typename == "AWSELBNetworkLoadBalancer"
		zone := lb.nlbAvailabilityZones[_]
	]
} else := []

glb_zones(lb) := x {
	x := [zone.name |
		lb.__typename == "AWSELBGatewayLoadBalancer"
		zone := lb.glbAvailabilityZones[_]
	]
} else := []

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
