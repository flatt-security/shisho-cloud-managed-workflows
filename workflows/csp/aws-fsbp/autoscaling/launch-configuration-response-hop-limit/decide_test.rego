package policy.aws.autoscaling.launch_configuration_response_hop_limit

import data.shisho
import future.keywords

test_whether_response_hop_limit_of_launch_configuration_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"launchConfiguration": {"metadataOptions": {"httpPutResponseHopLimit": 1}},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-3",
				"displayName": "test-group-3",
			},
			"launchConfiguration": {"metadataOptions": null},
		},
	]}}]}}
}

test_whether_response_hop_limit_of_launch_configuration_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"launchConfiguration": {"metadataOptions": {"httpPutResponseHopLimit": 2}},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"launchConfiguration": {"metadataOptions": {"httpPutResponseHopLimit": 3}},
		},
	]}}]}}
}
