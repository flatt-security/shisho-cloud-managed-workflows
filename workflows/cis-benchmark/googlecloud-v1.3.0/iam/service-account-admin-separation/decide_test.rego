package policy.googlecloud.iam.service_account_admin_separation

import data.shisho
import future.keywords

test_whether_admin_service_accounts_do_not_have_user_role if {
	# check if admin service accounts do not have user roles
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
					"role": "roles/iam.serviceAccountAdmin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/editor",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/iam.serviceAccountAdmin",
				"members": [{
					"id": "user:test-user-1@flatt.tech",
					"email": "test-user-1@flatt.tech",
					"deleted": false,
				}],
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514899999999",
				"displayName": "test-project-3",
			},
			"iamPolicy": {"bindings": [
				{
					"role": "roles/iam.serviceAccountAdmin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/iam.serviceAccountUser",
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
			"iamPolicy": {"bindings": []},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514891111111",
				"displayName": "test-project-5",
			},
			"iamPolicy": {"bindings": [{
				"role": "roles/iam.serviceAccountUser",
				"members": [],
			}]},
		},
	]}}

	# check if admin service accounts have user roles
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
					"role": "roles/iam.serviceAccountAdmin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/iam.serviceAccountUser",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514899999999",
				"displayName": "test-project-2",
			},
			"iamPolicy": {"bindings": [
				{
					"role": "roles/iam.serviceAccountAdmin",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
				{
					"role": "roles/iam.serviceAccountUser",
					"members": [{
						"id": "user:test-user-1@flatt.tech",
						"email": "test-user-1@flatt.tech",
						"deleted": false,
					}],
				},
			]},
		},
	]}}
}
