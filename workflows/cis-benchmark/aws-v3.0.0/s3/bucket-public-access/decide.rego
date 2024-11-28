package policy.aws.s3.bucket_public_access_block

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	config := bucket.publicAccessBlockConfiguration

	allowed := blocks_public_access(config)

	d := shisho.decision.aws.s3.bucket_public_access_block({
		"allowed": allow_if_excluded(allowed, bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_public_access_block_payload({"enabled": allowed}),
	})
}

blocks_public_access(config) {
	config.blockPublicAcls == true
	config.blockPublicPolicy == true
	config.ignorePublicAcls == true
	config.restrictPublicBuckets == true
} else = false

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
