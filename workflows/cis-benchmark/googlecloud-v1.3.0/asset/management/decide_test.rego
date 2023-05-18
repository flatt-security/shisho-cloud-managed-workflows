package policy.googlecloud.asset.management

import data.shisho
import future.keywords

test_whether_cloudasset_api_is_enabled_for_projects if {
	# check if the `cloudasset.googleapis.com` is enabled for projects
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "google-project|514893257777"},
			"services": [
				{
					"ProducerProjectId": "storage-component-prod",
					"name": "storage-component.googleapis.com",
				},
				{
					"ProducerProjectId": "google.com:cri-prod",
					"name": "cloudasset.googleapis.com",
				},
			],
		},
		{
			"metadata": {"id": "google-project|514893258888"},
			"services": [
				{
					"ProducerProjectId": "access-approval-api",
					"name": "accessapproval.googleapis.com",
				},
				{
					"ProducerProjectId": "google.com:cri-prod",
					"name": "cloudasset.googleapis.com",
				},
			],
		},
	]}}

	# check if the `cloudasset.googleapis.com` is enabled for projects
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "google-project|514893257777"},
			"services": [{
				"ProducerProjectId": "storage-component-prod",
				"name": "storage-component.googleapis.com",
			}],
		},
		{
			"metadata": {"id": "google-project|514893258888"},
			"services": [{
				"ProducerProjectId": "access-approval-api",
				"name": "accessapproval.googleapis.com",
			}],
		},
	]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"metadata": {"id": "google-project|514893257777"},
		"services": [],
	}]}}
}
