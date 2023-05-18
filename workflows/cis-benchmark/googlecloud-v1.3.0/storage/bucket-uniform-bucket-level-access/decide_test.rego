package policy.googlecloud.storage.bucket_uniform_bucket_level_access

import data.shisho
import future.keywords

test_whether_bucket_uniform_bucket_level_access_is_configured_for_storage_buckets if {
	# check if the uniform bucket level access is enabled for Google Cloud Storage buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"cloudStorage": {"buckets": [{
		"metadata": {"id": "google-cloud-bq-dataset|514893259785|test"},
		"uniformBucketLevelAccess": {"enabled": true},
	}]}}]}}

	# check if the uniform bucket level access is enabled for Google Cloud Storage buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"cloudStorage": {"buckets": [{
		"metadata": {"id": "google-cloud-bq-dataset|514893259785|test"},
		"uniformBucketLevelAccess": {"enabled": false},
	}]}}]}}
}
