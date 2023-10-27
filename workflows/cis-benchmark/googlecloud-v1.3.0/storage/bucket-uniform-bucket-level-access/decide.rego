package policy.googlecloud.storage.bucket_uniform_bucket_level_access

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	bucket := project.cloudStorage.buckets[_]

	allowed := bucket.uniformBucketLevelAccess.enabled == true

	d := shisho.decision.googlecloud.storage.bucket_uniform_bucket_level_access({
		"allowed": allowed,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.googlecloud.storage.bucket_uniform_bucket_level_access_payload({"uniform_access_enabled": bucket.uniformBucketLevelAccess.enabled}),
	})
}
