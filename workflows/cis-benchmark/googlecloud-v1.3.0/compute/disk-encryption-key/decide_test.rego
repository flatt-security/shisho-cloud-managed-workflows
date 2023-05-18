package policy.googlecloud.compute.disk_encryption_key

import data.shisho
import future.keywords

test_whether_disk_encryption_is_enabled_for_compute_engine_instance if {
	# check if the disk encryption is enabled without the Compute Engine default service account is used for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "test-kms-key-1",
						"kmsKeyServiceAccount": "test-name-1@project_id.iam.gserviceaccount.com",
						"sha256": "test-sha256-1",
					},
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903333"},
				"name": "yours",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "test-kms-key-2",
						"kmsKeyServiceAccount": "test-name-2@project_id.iam.gserviceaccount.com",
						"sha256": "test-sha256-2",
					},
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229904444"},
				"name": "test-3",
				"disks": [],
			},
		]},
	}]}}

	# check if the disk encryption is disabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "",
						"kmsKeyServiceAccount": "",
						"sha256": "",
					},
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "",
						"kmsKeyServiceAccount": "",
						"sha256": "",
					},
				}],
			},
		]},
	}]}}

	# check if the disk encryption is enabled for a Google Cloud Compute Engine instance
	# but the Compute Engine default service account is used
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "test-kms-key-1",
						"kmsKeyServiceAccount": "",
						"sha256": "",
					},
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "test-kms-key-2",
						"kmsKeyServiceAccount": "test-name@project_id.iam.gserviceaccount.com",
						"sha256": "test-sha256-2",
					},
				}],
			},
		]},
	}]}}

	# check if the disk encryption is enabled with the customer supplied service account for a Google Cloud Compute Engine instance
	# but the SHA256 is not supplied by the customer
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "test-kms-key-1",
						"kmsKeyServiceAccount": "",
						"sha256": "",
					},
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"disks": [{
					"deviceName": "test",
					"diskEncryptionKey": {
						"kmsKeyName": "test-kms-key-2",
						"kmsKeyServiceAccount": "test-name@project_id.iam.gserviceaccount.com",
						"sha256": "",
					},
				}],
			},
		]},
	}]}}
}
