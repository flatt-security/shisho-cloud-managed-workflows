package policy.googlecloud.firebaseauth.user_activity_logging_disabled

import data.shisho
import future.keywords

test_whether_user_activity_logging_is_enabled if {
	# check if user activity logging is enabled
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-1"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": [{
				"displayName": "test-tenant-1",
				"monitoring": {"requestLogging": {"enabled": true}},
			}]},
		},
		{
			"metadata": {"id": "test-project-5"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": []}, # no tenant. in this case, `firebaseAuthentication.settings.userActivityLoggingDisabled` should be only checked
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-6",
					"monitoring": {"requestLogging": {"enabled": true}},
				},
				{
					"displayName": "test-tenant-61",
					"monitoring": {"requestLogging": {"enabled": true}},
				},
			]},
		},
	]}}
}

test_whether_user_activity_logging_is_disabled if {
	# check if user activity logging is disabled
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 7 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "test-project-2"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": true}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-2",
					"monitoring": {"requestLogging": {"enabled": true}},
				},
				{
					"displayName": "test-tenant-4",
					"monitoring": {"requestLogging": {"enabled": false}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-3"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-3",
					"monitoring": {"requestLogging": {"enabled": true}},
				},
				{
					"displayName": "test-tenant-5",
					"monitoring": {"requestLogging": {"enabled": false}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-4"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": true}},
			"identityPlatform": {"tenants": []},
		},
		{
			"metadata": {"id": "test-project-6"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-6",
					"monitoring": {"requestLogging": {"enabled": false}},
				},
				{
					"displayName": "test-tenant-61",
					"monitoring": {"requestLogging": {"enabled": false}},
				},
			]},
		},
		{
			"metadata": {"id": "test-project-7"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-7",
					"monitoring": null, # if `monitoring` is null, `monitoring.requestLogging.enabled` is the default value which is false
				},
				{
					"displayName": "test-tenant-71",
					"monitoring": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-8"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": true}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-8",
					"monitoring": null,
				},
				{
					"displayName": "test-tenant-81",
					"monitoring": null,
				},
			]},
		},
		{
			"metadata": {"id": "test-project-9"},
			"firebaseAuthentication": {"settings": {"userActivityLoggingDisabled": false}},
			"identityPlatform": {"tenants": [
				{
					"displayName": "test-tenant-9",
					"monitoring": {"requestLogging": null}, # if `monitoring.requestLogging` is null, `monitoring.requestLogging.enabled` is the default value which is false
				},
				{
					"displayName": "test-tenant-91",
					"monitoring": {"requestLogging": null},
				},
			]},
		},
	]}}
}
