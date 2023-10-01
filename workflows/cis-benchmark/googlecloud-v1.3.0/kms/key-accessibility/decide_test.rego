package policy.googlecloud.kms.key_accessibility

import data.shisho
import future.keywords

test_whether_publicly_accessible_of_kms_keys_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"kms": {"keyRings": [
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|514897777777|projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
				"displayName": "projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"members": [],
			}]},
		}]},
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|514897777777|projects/test-project-1/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
				"displayName": "projects/test-project-1/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"members": [],
			}]},
		}]},
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|514897777777|projects/test-project-1/locations/us-west1/keyRings/test-keyring-2/cryptoKeys/test-key-2",
				"displayName": "projects/test-project-1/locations/us-west1/keyRings/test-keyring-2/cryptoKeys/test-key-2",
			},
			"iamPolicy": {"bindings": []},
		}]},
	]}}]}}
}

test_whether_publicly_accessible_of_kms_keys_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"kms": {"keyRings": [
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|514897777777|projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
				"displayName": "projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"members": [
					{"id": "allUsers"},
					{"id": "allAuthenticatedUsers"},
				],
			}]},
		}]},
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|514897777777|projects/test-project-1/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
				"displayName": "projects/test-project-1/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"members": [{"id": "allAuthenticatedUsers"}],
			}]},
		}]},
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|514897777777|projects/test-project-1/locations/us-west1/keyRings/test-keyring-2/cryptoKeys/test-key-2",
				"displayName": "projects/test-project-1/locations/us-west1/keyRings/test-keyring-2/cryptoKeys/test-key-2",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"members": [{"id": "allUsers"}],
			}]},
		}]},
	]}}]}}
}
