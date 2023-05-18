package policy.aws.s3.bucket_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	rules := bucket.encryptionConfiguration.rules

	allowed := is_allowed(rules)

	d := shisho.decision.aws.s3.bucket_encryption({
		"allowed": allowed,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_encryption_payload({"algorithms": get_algorithms(rules)}),
	})
}

is_allowed(rules) {
	rule := rules[_]
	rule.keyEnabled == true
	any([
		rule.encryptionByDefault.sseAlgorithm == "AES256",
		rule.encryptionByDefault.sseAlgorithm == "AWS_KMS",
		rule.encryptionByDefault.sseAlgorithm == "SSE_KMS",
		rule.encryptionByDefault.sseAlgorithm == "SSE_S3",
	])
} else = false {
	true
}

get_algorithms(rules) = x {
	x := [rule.encryptionByDefault.sseAlgorithm |
		rule := rules[_]
	]
}
