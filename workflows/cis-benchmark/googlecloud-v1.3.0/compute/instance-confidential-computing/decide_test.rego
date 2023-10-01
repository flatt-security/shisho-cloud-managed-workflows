package policy.googlecloud.compute.instance_confidential_computing

import data.shisho
import future.keywords

test_whether_confidential_computing_is_enabled_for_compute_engine_instance if {
	# check if the confidential computing is enabled for a Google Cloud Compute Engine instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-ce-instance|514897777777|us-central1-a|3545084786847777777",
				"displayName": "instance-1",
			},
			"machineType": "n2d-highcpu-48",
			"confidentialInstanceConfiguration": {"enableConfidentialCompute": true},
		},
		{
			"metadata": {
				"id": "googlecloud-ce-instance|514897777777|asia-northeast2-a|3785461238728888888",
				"displayName": "instance-2",
			},
			"machineType": "custom-20-61440-ext",
			"confidentialInstanceConfiguration": null,
		},
		{
			"metadata": {
				"id": "googlecloud-ce-instance|514897777777|asia-northeast2-a|3785461238729999999",
				"displayName": "instance-3",
			},
			"machineType": "n2d-highcpu-64",
			"confidentialInstanceConfiguration": {"enableConfidentialCompute": true},
		},
		{
			"metadata": {
				"id": "googlecloud-ce-instance|514897777777|asia-northeast2-a|3785461238720000000",
				"displayName": "instance-4",
			},
			"machineType": "custom-20-61440-ext",
			"confidentialInstanceConfiguration": {"enableConfidentialCompute": false},
		},
	]}}]}}

	# check if the confidential computing is not enabled for a Google Cloud Compute Engine instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-ce-instance|514897777777|us-central1-a|3545084786847777777",
				"displayName": "instance-1",
			},
			"machineType": "n2d-highcpu-48",
			"confidentialInstanceConfiguration": {"enableConfidentialCompute": false},
		},
		{
			"metadata": {
				"id": "googlecloud-ce-instance|514897777777|asia-northeast2-a|3785461238729999999",
				"displayName": "instance-3",
			},
			"machineType": "n2d-highcpu-64",
			"confidentialInstanceConfiguration": {"enableConfidentialCompute": false},
		},
	]}}]}}
}
