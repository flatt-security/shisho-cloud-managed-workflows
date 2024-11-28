package policy.googlecloud.firebaseauth.accounts_can_be_created_by_end_user

import data.shisho
import future.keywords

test_whether_end_user_cannot_create_their_account if {
	# check if the end user cannot create their account per project and tenant
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-1",
				"client": {"permissions": {"disabledUserSignup": true}},
			}]},
		},
		{
			"metadata": {"id": "test-project-5"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-5",
					"client": {"permissions": {"disabledUserSignup": true}},
				},
				{
					"displayName": "test-tenant-51",
					"client": {"permissions": {"disabledUserSignup": true}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": false}},
			"identityPlatform": {"tenants": []}, # no tenant. in this case, `firebaseAuthentication.settings.accountsCanBeCreatedByEndUser` should be only checked
		},
	]}}
}

test_whether_end_user_can_create_their_account if {
	# check if the end user can create their account per project and tenant
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 7 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"client": {"permissions": {"disabledUserSignup": false}},
				},
				{
					"displayName": "test-tenant-4",
					"client": {"permissions": {"disabledUserSignup": true}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": true}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-3",
				"client": {"permissions": {"disabledUserSignup": false}},
			}]},
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": true}},
			"identityPlatform": {"tenants": []},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-7",
					"client": null, # if `client` is null, `client.permissions.disabledUserSignup` is the default value which is false
				},
				{
					"displayName": "test-tenant-71",
					"client": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-8"},
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": true}},
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
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": true}},
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
			"firebaseAuthentication": {"settings": {"accountsCanBeCreatedByEndUser": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-10",
					"client": {"permissions": null}, # if `client.permissions` is null, `client.permissions.disabledUserSignup` is the default value which is false
				},
				{
					"displayName": "test-tenant-101",
					"client": {"permissions": null},
				},
			]},
		},
	]}}
}
