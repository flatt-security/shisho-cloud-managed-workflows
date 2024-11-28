package policy.aws.networking.vpc_flow_logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]

	allowed := count(vpc.flowLogs) > 0

	d := shisho.decision.aws.networking.vpc_flow_logging({
		"allowed": allow_if_excluded(allowed, vpc),
		"subject": vpc.metadata.id,
		"payload": shisho.decision.aws.networking.vpc_flow_logging_payload({"enabled": allowed}),
	})
}

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
