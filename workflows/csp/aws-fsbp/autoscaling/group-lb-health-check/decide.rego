package policy.aws.autoscaling.group_lb_health_check

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.autoScaling.groups[_]

	clbs = classic_load_balancer_names(group.loadBalancer.classicLoadBalancers)
	count(clbs) > 0

	d := shisho.decision.aws.autoscaling.group_lb_health_check({
		"allowed": allow_if_excluded(group.healthCheckType == "ELB", group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.autoscaling.group_lb_health_check_payload({
			"health_check_type": group.healthCheckType,
			"classic_load_balancers": clbs,
		}),
	})
}

classic_load_balancer_names(classic_load_balancers) = x {
	x := [classic_load_balancer.name |
		classic_load_balancer := classic_load_balancers[_]
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
