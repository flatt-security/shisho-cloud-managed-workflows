package policy.aws.elb.logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	access_log := lb.attributes.accessLog
	allowed := access_log.enabled

	d := shisho.decision.aws.alb.logging({
		"allowed": allow_if_excluded(allowed, lb),
		"subject": lb.metadata.id,
		"payload": shisho.decision.aws.alb.logging_payload({
			"log_enabled": access_log.enabled,
			"log_bucket": string_or_default(access_log.s3BucketName, ""),
			"log_prefix": string_or_default(access_log.s3BucketPrefix, ""),
		}),
	})
}

string_or_default(s, d) = s {
	s != null
} else := d

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
