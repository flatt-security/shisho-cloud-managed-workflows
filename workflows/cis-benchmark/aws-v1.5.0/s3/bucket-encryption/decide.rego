package policy.aws.s3.bucket_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	rules := bucket.encryptionConfiguration.rules

	allowed := includes_accepted_encryption_rule(rules)

	d := shisho.decision.aws.s3.bucket_encryption({
		"allowed": allow_if_excluded(allowed, bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_encryption_payload({"algorithms": get_algorithms(rules)}),
	})
}

includes_accepted_encryption_rule(rules) {
	rule := rules[_]

	any([
		rule.encryptionByDefault.sseAlgorithm == "AES256",
		rule.encryptionByDefault.sseAlgorithm == "AWS_KMS",
		rule.encryptionByDefault.sseAlgorithm == "SSE_KMS",
		rule.encryptionByDefault.sseAlgorithm == "SSE_S3",
	])
} else := false

get_algorithms(rules) = x {
	x := [rule.encryptionByDefault.sseAlgorithm |
		rule := rules[_]
	]
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
