package policy.aws.s3.bucket_kms_encryption

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	rules := bucket.encryptionConfiguration.rules

	allowed := is_allowed(rules)

	d := shisho.decision.aws.s3.bucket_kms_encryption({
		"allowed": allow_if_excluded(allowed, bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_kms_encryption_payload({"encryption_rules": get_algorithms(rules)}),
	})
}

is_allowed(rules) {
	rule := rules[_]
	rule.encryptionByDefault.kmsMasterKeyId != ""
	rule.encryptionByDefault.sseAlgorithm in ["AWS_KMS", "SSE_KMS", "AWS_KMS_DSSE"]
} else = false

get_algorithms(rules) = x {
	x := [{"algorithm": rule.encryptionByDefault.sseAlgorithm, "kms_key_id": rule.encryptionByDefault.kmsMasterKeyId} |
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
