package policy.googlecloud.firebaseauth.is_password_strength_insufficient

import data.shisho
import future.keywords

test_whether_password_strength_is_sufficient if {
	# check if password strength is sufficient
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-1",
				"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 8}}]},
			}]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": []}, # no tenant. in this case, `firebaseAuthentication.settings.passwordPolicy.passwordPolicyVersions.customStrengthOptions.minimumLength` should be only checked
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-6",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 8}}]},
				},
				{
					"displayName": "test-tenant-61",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 8}}]},
				},
			]},
		},
	]}}
}

test_whether_password_strength_is_insufficient if {
	# check if password strength is insufficient
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 7 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 7}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 8}}]},
				},
				{
					"displayName": "test-tenant-4",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 8}}]},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-3",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 7}}]},
				},
				{
					"displayName": "test-tenant-7",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": {"minimumPasswordLength": 8}}]},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 7}}]}}},
			"identityPlatform": {"tenants": []},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-7",
					"passwordPolicyConfiguration": null, # if `passwordPolicyConfiguration` is null, `passwordPolicyConfiguration.versions.customStrengthOptions.minimumPasswordLength` is the default value which is 6
				},
				{
					"displayName": "test-tenant-71",
					"passwordPolicyConfiguration": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-8"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 7}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-8",
					"passwordPolicyConfiguration": null,
				},
				{
					"displayName": "test-tenant-81",
					"passwordPolicyConfiguration": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-9"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-9",
					"passwordPolicyConfiguration": {"versions": []}, # if the length of `versions` is 0, `passwordPolicyConfiguration.versions.customStrengthOptions.minimumPasswordLength` is the default value which is 6
				},
				{
					"displayName": "test-tenant-91",
					"passwordPolicyConfiguration": {"versions": []},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-8"},
			"firebaseAuthentication": {"settings": {"passwordPolicy": {"passwordPolicyVersions": [{"customStrengthOptions": {"minimumLength": 8}}]}}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-8",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": null}]}, # if `customStrengthOptions` is null, `passwordPolicyConfiguration.versions.customStrengthOptions.minimumPasswordLength` is the default value which is 6
				},
				{
					"displayName": "test-tenant-81",
					"passwordPolicyConfiguration": {"versions": [{"customStrengthOptions": null}]},
				},
			]},
		},
	]}}
}
