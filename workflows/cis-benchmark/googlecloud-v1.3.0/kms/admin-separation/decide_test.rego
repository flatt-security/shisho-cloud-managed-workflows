package policy.googlecloud.kms.admin_separation

import data.shisho
import future.keywords

test_whether_kms_admins_have_only_admin_role if {
	# check if KMS admins have only the KMS admin role
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"iamPolicy": {"bindings": [
				{
					"role": "roles/cloudkms.admin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/editor",
					"members": [{
						"id": "user:test-user-3@flatt.tech",
						"email": "test-user-3@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/owner",
					"members": [
						{
							"id": "user:test-user-2@flatt.tech",
							"email": "test-user-2@flatt.tech",
							"deleted": false,
						},
						{
							"id": "user:test-user-1@flatt.tech",
							"email": "test-user-1@flatt.tech",
							"deleted": false,
						},
					],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"iamPolicy": {"bindings": []},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514899999999",
				"displayName": "test-project-3",
			},
			"iamPolicy": {"bindings": [
				{
					"role": "roles/cloudkms.admin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyDecrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": true,
					}],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514890000000",
				"displayName": "test-project-4",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/owner",
				"members": [
					{
						"id": "user:test-user-2@flatt.tech",
						"email": "test-user-2@flatt.tech",
						"deleted": false,
					},
					{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					},
				],
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514891111111",
				"displayName": "test-project-5",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/owner",
				"members": [],
			}]},
		},
	]}}

	# check if KMS admins do not have any other KMS roles
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"iamPolicy": {"bindings": [
				{
					"role": "roles/cloudkms.admin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyDecrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyEncrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/editor",
					"members": [{
						"id": "user:test-user-3@flatt.tech",
						"email": "test-user-3@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/owner",
					"members": [
						{
							"id": "user:test-user-2@flatt.tech",
							"email": "test-user-2@flatt.tech",
							"deleted": false,
						},
						{
							"id": "user:test-user-1@flatt.tech",
							"email": "test-user-1@flatt.tech",
							"deleted": false,
						},
					],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"iamPolicy": {"bindings": [
				{
					"role": "roles/cloudkms.admin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyDecrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyEncrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/editor",
					"members": [{
						"id": "user:test-user-3@flatt.tech",
						"email": "test-user-3@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/owner",
					"members": [
						{
							"id": "user:test-user-2@flatt.tech",
							"email": "test-user-2@flatt.tech",
							"deleted": false,
						},
						{
							"id": "user:test-user-1@flatt.tech",
							"email": "test-user-1@flatt.tech",
							"deleted": false,
						},
					],
				},
			]},
		},
	]}}
}
