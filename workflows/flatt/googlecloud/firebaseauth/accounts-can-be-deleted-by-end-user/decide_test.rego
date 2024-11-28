package policy.googlecloud.firebaseauth.accounts_can_be_deleted_by_end_user

import data.shisho
import future.keywords

test_whether_end_user_cannot_delete_their_account if {
	# check if the end user cannot delete their account
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-1",
				"client": {"permissions": {"disabledUserDeletion": true}},
			}]},
		},
		{
			"metadata": {"id": "test-project-5"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-5",
					"client": {"permissions": {"disabledUserDeletion": true}},
				},
				{
					"displayName": "test-tenant-6",
					"client": {"permissions": {"disabledUserDeletion": true}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-10"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": false}},
			"identityPlatform": {"tenants": []}, # no tenant. in this case, `firebaseAuthentication.settings.accountsCanBeDeletedByEndUser` should be only checked
		},
	]}}
}

test_whether_end_user_can_delete_their_account if {
	# check if the end user can delete their account
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 7 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"client": {"permissions": {"disabledUserDeletion": true}},
				},
				{
					"displayName": "test-tenant-4",
					"client": {"permissions": {"disabledUserDeletion": false}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": true}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-3",
				"client": {"permissions": {"disabledUserDeletion": false}},
			}]},
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": true}},
			"identityPlatform": {"tenants": []},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-7",
					"client": null, # if `client` is null, `client.permissions.accountsCanBeDeletedByEndUser` is the default value which is false
				},
				{
					"displayName": "test-tenant-71",
					"client": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-8"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": true}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-8",
					"client": null,
				},
				{
					"displayName": "test-tenant-81",
					"client": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-9"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": true}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-9",
					"client": {"permissions": null},
				},
				{
					"displayName": "test-tenant-91",
					"client": {"permissions": null},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-10"},
			"firebaseAuthentication": {"settings": {"accountsCanBeDeletedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-10",
					"client": {"permissions": null}, # if `client.permissions` is null, `client.permissions.accountsCanBeDeletedByEndUser` is the default value which is false
				},
				{
					"displayName": "test-tenant-101",
					"client": {"permissions": null},
				},
			]},
		},
	]}}
}
