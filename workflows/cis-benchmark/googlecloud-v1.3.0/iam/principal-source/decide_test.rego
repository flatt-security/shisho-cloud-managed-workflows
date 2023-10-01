package policy.googlecloud.iam.principal_source

import data.shisho
import future.keywords

test_whether_principal_sources_for_projects_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"iamPolicy": {"bindings": []},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"iamPolicy": {"bindings": [{"members": []}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514899999999",
				"displayName": "test-project-3",
			},
			"iamPolicy": {"bindings": [{"members": [
				{
					"__typename": "GoogleCloudIAMPrincipalUser",
					"id": "user:test-user-1@flatt.tech",
					"email": "test-user-1@flatt.tech",
					"deleted": true,
				},
				{
					"__typename": "GoogleCloudIAMPrincipalGroup",
					"id": "user:test-group-1@flatt.tech",
					"email": "test-group-1@flatt.tech",
					"deleted": true,
				},
			]}]},
		},
	]}}
}

test_whether_principal_sources_for_projects_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"iamPolicy": {"bindings": [{"members": [
				{
					"__typename": "GoogleCloudIAMPrincipalUser",
					"id": "user:test-user-1@flatt.tech",
					"email": "test-user-1@flatt.tech",
					"deleted": false,
				},
				{
					"__typename": "GoogleCloudIAMPrincipalGroup",
					"id": "user:test-group-1@flatt.tech",
					"email": "test-group-1@flatt.tech",
					"deleted": false,
				},
			]}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514899999999",
				"displayName": "test-project-3",
			},
			"iamPolicy": {"bindings": [{"members": [
				{
					"__typename": "GoogleCloudIAMPrincipalUser",
					"id": "user:test-user-2@flatt.tech",
					"email": "test-user-2@flatt.tech",
					"deleted": false,
				},
				{
					"__typename": "GoogleCloudIAMPrincipalGroup",
					"id": "user:test-group-2@flatt.tech",
					"email": "test-group-2@flatt.tech",
					"deleted": false,
				},
			]}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514890000000",
				"displayName": "test-project-4",
			},
			"iamPolicy": {"bindings": [{"members": [{
				"__typename": "GoogleCloudIAMPrincipalDomain",
				"id": "domain:example.tech",
				"domain": "example.tech",
			}]}]},
		},
	]}}
}
