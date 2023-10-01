package policy.googlecloud.credential.api_keys_scope

import data.shisho
import future.keywords

test_whether_api_keys_are_restricted_by_apis if {
	# check if the API keys are restricted by APIs
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"credentials": {"apiKeys": [{
				"metadata": {
					"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428faca562a",
					"displayName": "test key 1",
				},
				"deletedAt": null,
				"restriction": {"apiTargets": [{
					"methods": [],
					"service": "sql-component.googleapis.com",
				}]},
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"credentials": {"apiKeys": [
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|514898888888|47bf78cc-9c32-42c6-a541-d428f8888888",
						"displayName": "test key 2",
					},
					"deletedAt": null,
					"restriction": {"apiTargets": [{
						"methods": [],
						"service": "sql-component.googleapis.com",
					}]},
				},
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|51489999999|47bf78cc-9c32-42c6-a541-d428f9999999",
						"displayName": "test key 3",
					},
					"deletedAt": "2022-01-01T00:00:00Z",
					"restriction": null,
				},
			]},
		},
	]}}

	# check if the API keys are not restricted by APIs
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"credentials": {"apiKeys": [{
				"metadata": {
					"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428faca562a",
					"displayName": "test key 1",
				},
				"deletedAt": null,
				"restriction": {"apiTargets": []},
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"credentials": {"apiKeys": [
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|514898888888|47bf78cc-9c32-42c6-a541-d428f8888888",
						"displayName": "test key 2",
					},
					"deletedAt": null,
					"restriction": {"apiTargets": []},
				},
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|51489999999|47bf78cc-9c32-42c6-a541-d428f9999999",
						"displayName": "test key 3",
					},
					"deletedAt": null,
					"restriction": null,
				},
			]},
		},
	]}}
}
