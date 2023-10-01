package policy.aws.elb.alb_header

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	enabled := lb.attributes.dropInvalidHeaderFields
	allowed := enabled

	d := shisho.decision.aws.alb.invalid_header_handling({
		"allowed": allow_if_excluded(allowed, lb),
		"subject": lb.metadata.id,
		"payload": shisho.decision.aws.alb.invalid_header_handling_payload({"invalid_header_mitigation_enabled": enabled}),
	})
}

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	mode := lb.attributes.desyncMitigationMode
	allowed := allowed_desync_mitigation_mode(mode)

	d := shisho.decision.aws.alb.desync_mitigation({
		"allowed": allowed,
		"subject": lb.metadata.id,
		"payload": shisho.decision.aws.alb.desync_mitigation_payload({"desync_mitigation_mode": mode}),
	})
}

allowed_desync_mitigation_mode(m) {
	m == "STRICTEST"
} else {
	m == "DEFENSIVE"
} else := false

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
