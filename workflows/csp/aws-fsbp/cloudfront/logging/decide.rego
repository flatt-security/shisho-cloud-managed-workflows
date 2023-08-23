package policy.aws.cloudfront.logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := has_logging_bucket(dist.config)
	d := shisho.decision.aws.cloudfront.logging({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.logging_payload({"bucket_id": logging_bucket_id(dist.config)}),
	})
}

has_logging_bucket(cfg) {
	logging_bucket_id(cfg) != ""
} else := false

logging_bucket_id(cfg) := cfg.logging.bucketId {
	cfg.logging != null
	cfg.logging.bucketId != ""
} else := ""

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
