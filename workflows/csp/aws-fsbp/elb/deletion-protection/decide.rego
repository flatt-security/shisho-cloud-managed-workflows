package policy.aws.elb.deletion_protection

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	enabled := lb.attributes.enabledDeletionProtection
	allowed := enabled

	d := shisho.decision.aws.alb.delete_protection({
		"allowed": allow_if_excluded(allowed, lb),
		"subject": lb.metadata.id,
		"payload": shisho.decision.aws.alb.delete_protection_payload({"deletion_protection_enabled": enabled}),
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
