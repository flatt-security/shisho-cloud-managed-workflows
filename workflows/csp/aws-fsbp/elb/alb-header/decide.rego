package policy.aws.elb.alb_header

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	enabled := lb.attributes.dropInvalidHeaderFields
	allowed := enabled

	d := shisho.decision.aws.alb.invalid_header_handling({
		"allowed": allowed,
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
