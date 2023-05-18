package policy.aws.s3.bucket_public_access_block

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	config := bucket.publicAccessBlockConfiguration

	allowed := blocks_public_access(config)

	d := shisho.decision.aws.s3.bucket_public_access_block({
		"allowed": allowed,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_public_access_block_payload({"enabled": allowed}),
	})
}

blocks_public_access(config) {
	config.blockPublicAcls == true
	config.blockPublicPolicy == true
	config.ignorePublicAcls == true
	config.restrictPublicBuckets == true
} else = false {
	true
}
