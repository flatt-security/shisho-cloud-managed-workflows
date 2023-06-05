package policy.aws.cloudfront.logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := has_logging_bucket(dist.config)
	d := shisho.decision.aws.cloudfront.logging({
		"allowed": allowed,
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
