package policy.googlecloud.firebaseauth.password_policy_disabled

import data.shisho
import future.keywords

test_whether_password_policy_enabled if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-3",
					"passwordPolicyConfiguration": {"enforcementState": "ENFORCE"},
				},
				{
					"displayName": "test-tenant-5",
					"passwordPolicyConfiguration": {"enforcementState": "ENFORCE"},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": false}},
			"identityPlatform": {"tenants": []}, # no tenant. in this case, `firebaseAuthentication.settings.passwordPolicyDisabled` should be only checked
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-3",
				"passwordPolicyConfiguration": {"enforcementState": "ENFORCE"},
			}]},
		},
	]}}
}

test_whether_password_policy_disabled if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"passwordPolicyConfiguration": {"enforcementState": "ENFORCE"},
				},
				{
					"displayName": "test-tenant-4",
					"passwordPolicyConfiguration": {"enforcementState": "OFF"},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": true}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-3",
					"passwordPolicyConfiguration": {"enforcementState": "ENFORCE"},
				},
				{
					"displayName": "test-tenant-5",
					"passwordPolicyConfiguration": {"enforcementState": "ENFORCE"},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": true}},
			"identityPlatform": {"tenants": []},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"passwordPolicyDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-7",
					"passwordPolicyConfiguration": null, # if `passwordPolicyConfiguration` is null, the password policy is disabled as default
				},
				{
					"displayName": "test-tenant-71",
					"passwordPolicyConfiguration": null,
				},
			]},
		},
	]}}
}
