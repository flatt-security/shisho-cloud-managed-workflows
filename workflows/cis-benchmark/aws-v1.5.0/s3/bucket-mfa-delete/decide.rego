package policy.aws.s3.bucket_mfa_delete

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	allowed := versioning_needs_mfa(bucket.versioning)

	d := shisho.decision.aws.s3.bucket_mfa_delete({
		"allowed": allowed,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_mfa_delete_payload({"mfa_enabled": allowed}),
	})
}

versioning_needs_mfa(v) {
	v.status == "ENABLED"
	v.mfaDelete == "ENABLED"
} else = false {
	true
}
