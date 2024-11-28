package policy.aws.autoscaling.group_availability_zones

import data.shisho
import future.keywords

test_whether_availability_zones_for_autoscaling_groups_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"availabilityZones": [
				"ap-northeast-1a",
				"ap-northeast-1c",
			],
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"availabilityZones": [
				"ap-northeast-1a",
				"ap-northeast-1c",
				"ap-northeast-1d",
			],
		},
	]}}]}}
}

test_whether_availability_zones_for_autoscaling_groups_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"availabilityZones": ["ap-northeast-1c"],
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-3",
				"displayName": "test-group-3",
			},
			"availabilityZones": ["ap-northeast-1a"],
		},
	]}}]}}
}
