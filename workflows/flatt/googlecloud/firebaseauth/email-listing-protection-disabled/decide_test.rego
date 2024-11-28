package policy.googlecloud.firebaseauth.email_listing_protection_disabled

import data.shisho
import future.keywords

test_whether_email_listing_protection_is_enabled if {
	# check if email listing protection is enabled
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-1",
				"emailPrivacyConfiguration": {"enableImprovedEmailPrivacy": true},
			}]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-4",
					"emailPrivacyConfiguration": {"enableImprovedEmailPrivacy": true},
				},
				{
					"displayName": "test-tenant-41",
					"emailPrivacyConfiguration": {"enableImprovedEmailPrivacy": true},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-5"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": false}},
			"identityPlatform": {"tenants": []}, # no tenant. in this case, `firebaseAuthentication.settings.emailListingProtectionDisabled` should be only checked
		},
	]}}
}

test_whether_email_listing_protection_is_disabled if {
	# check if email listing protection is disabled
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"emailPrivacyConfiguration": {"enableImprovedEmailPrivacy": true},
				},
				{
					"displayName": "test-tenant-4",
					"emailPrivacyConfiguration": {"enableImprovedEmailPrivacy": false},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-3",
				"emailPrivacyConfiguration": {"enableImprovedEmailPrivacy": false},
			}]},
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": true}},
			"identityPlatform": {"tenants": []},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"emailListingProtectionDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-7",
					"emailPrivacyConfiguration": null, # if `emailPrivacyConfiguration` is null, `emailPrivacyConfiguration.enableImprovedEmailPrivacy` is the default value which is false
				},
				{
					"displayName": "test-tenant-71",
					"emailPrivacyConfiguration": null,
				},
			]},
		},
	]}}
}
