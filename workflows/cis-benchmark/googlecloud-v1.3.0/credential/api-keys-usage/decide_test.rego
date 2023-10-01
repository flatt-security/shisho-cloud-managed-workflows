package policy.googlecloud.credential.api_keys_usage

import data.shisho
import future.keywords

test_whether_api_keys_are_not_created_for_projects if {
	# check if the API keys are not created for projects
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"credentials": {"apiKeys": []},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"credentials": {"apiKeys": [{
				"name": "projects/514897777777/locations/global/keys/47bf78cc-9c32-42c6-a541-d428f7777777",
				"displayName": "test key 1",
				"deletedAt": "2022-01-01T00:00:00Z",
			}]},
		},
	]}}

	# check if the API keys are created for projects
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"credentials": {"apiKeys": [{
				"name": "projects/514897777777/locations/global/keys/47bf78cc-9c32-42c6-a541-d428f7777777",
				"displayName": "test key 1",
				"deletedAt": null,
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"credentials": {"apiKeys": [
				{
					"name": "projects/514898888888/locations/global/keys/47bf78cc-9c32-42c6-a541-d428f8888888",
					"displayName": "test key 2",
					"deletedAt": null,
				},
				{
					"name": "projects/514898888888/locations/global/keys/47bf78cc-9c32-42c6-a541-d428f9999999",
					"displayName": "test key 3",
					"deletedAt": null,
				},
			]},
		},
	]}}
}
