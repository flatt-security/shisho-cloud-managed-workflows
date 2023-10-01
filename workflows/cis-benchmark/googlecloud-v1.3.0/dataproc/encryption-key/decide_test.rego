package policy.googlecloud.dataproc.encryption_key

import data.shisho
import future.keywords

test_whether_clusters_are_encrypted_by_encryption_keys if {
	# check if the clusters are encrypted by encryption keys
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{"dataproc": {"clusters": [{
			"metadata": {
				"id": "googlecloud-dataproc-cluster|514897777777|47bf78cc-9c32-42c6-a541-d428faca562a",
				"displayName": "cluster 1",
			},
			"configuration": {"encryptionConfiguration": {"gcePdKmsKeyName": "projects/514897777777/locations/global/keyRings/cluster-1/cryptoKeys/key-1"}},
		}]}},
		{"dataproc": {"clusters": [{
			"metadata": {
				"id": "googlecloud-dataproc-cluster|514898888888|47bf78cc-9c32-42c6-a541-d428f9999999",
				"displayName": "cluster 3",
			},
			"configuration": {"encryptionConfiguration": {"gcePdKmsKeyName": "projects/514898888888/locations/global/keyRings/cluster-3/cryptoKeys/key-2"}},
		}]}},
	]}}

	# check if the clusters are encrypted by encryption keys
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{"dataproc": {"clusters": [{
			"metadata": {
				"id": "googlecloud-dataproc-cluster|514897777777|47bf78cc-9c32-42c6-a541-d428faca562a",
				"displayName": "cluster 1",
			},
			"configuration": {"encryptionConfiguration": {"gcePdKmsKeyName": ""}},
		}]}},
		{"dataproc": {"clusters": [
			{
				"metadata": {
					"id": "googlecloud-dataproc-cluster|514898888888|47bf78cc-9c32-42c6-a541-d428f8888888",
					"displayName": "cluster 2",
				},
				"configuration": {"encryptionConfiguration": {"gcePdKmsKeyName": ""}},
			},
			{
				"metadata": {
					"id": "googlecloud-dataproc-cluster|514898888888|47bf78cc-9c32-42c6-a541-d428f9999999",
					"displayName": "cluster 3",
				},
				"configuration": {"encryptionConfiguration": {"gcePdKmsKeyName": ""}},
			},
		]}},
	]}}
}
