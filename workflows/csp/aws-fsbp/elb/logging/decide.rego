package policy.aws.elb.logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	access_log := lb.attributes.accessLog
	allowed := access_log.enabled

	d := shisho.decision.aws.alb.logging({
		"allowed": allowed,
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
