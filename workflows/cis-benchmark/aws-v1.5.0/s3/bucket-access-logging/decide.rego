package policy.aws.s3.bucket_access_logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	allowed := bucket.logging != null

	d := shisho.decision.aws.s3.bucket_access_logging({
		"allowed": allowed,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_access_logging_payload({"enabled": allowed}),
	})
}
