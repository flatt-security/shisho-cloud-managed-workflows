package policy.aws.autoscaling.launch_configuration_public_ip

import data.shisho
import future.keywords

test_whether_public_ip_for_autoscaling_groups_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"launchConfiguration": {"associatePublicIpAddress": false},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"launchConfiguration": {"associatePublicIpAddress": false},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-3",
				"displayName": "test-group-3",
			},
			"launchConfiguration": null,
		},
	]}}]}}
}

test_whether_public_ip_for_autoscaling_groups_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"launchConfiguration": {"associatePublicIpAddress": true},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"launchConfiguration": {"associatePublicIpAddress": true},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-3",
				"displayName": "test-group-3",
			},
			"launchConfiguration": null,
		},
	]}}]}}
}
