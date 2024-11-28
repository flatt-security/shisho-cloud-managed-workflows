package policy.googlecloud.firebaseauth.anonymous_login_enabled

import data.shisho
import future.keywords

test_whether_anonymous_login_is_disabled if {
	# check if the anonymous login is disabled
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-1",
				"enableAnonymousUser": false,
			}]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-4",
					"enableAnonymousUser": false,
				},
				{
					"displayName": "test-tenant-41",
					"enableAnonymousUser": false,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-5"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": false}},
			"identityPlatform": {"tenants": []}, # no tenant, in this case, firebaseAuthentication.settings.anonymousLoginEnabled should be only checked
		},
	]}}
}

test_whether_anonymous_login_is_enabled if {
	# check if the anonymous login is enabled
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"enableAnonymousUser": false,
				},
				{
					"displayName": "test-tenant-3",
					"enableAnonymousUser": true,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": true}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-4",
				"enableAnonymousUser": false,
			}]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-4",
					"enableAnonymousUser": true,
				},
				{
					"displayName": "test-tenant-41",
					"enableAnonymousUser": true,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"anonymousLoginEnabled": true}},
			"identityPlatform": {"tenants": []},
		},
	]}}
}
