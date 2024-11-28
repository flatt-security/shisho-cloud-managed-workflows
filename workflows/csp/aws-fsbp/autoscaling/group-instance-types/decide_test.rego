package policy.aws.autoscaling.group_instance_types

import data.shisho
import future.keywords

test_whether_instance_types_for_autoscaling_groups_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|ecs-test-ECSAutoScalingGroup-1BAGMH5EZ9ZCW",
				"displayName": "ecs-test-ECSAutoScalingGroup-1BAGMH5EZ9ZCW",
			},
			"availabilityZones": [
				"ap-northeast-1a",
				"ap-northeast-1c",
				"ap-northeast-1d",
			],
			"mixedInstancesPolicy": null,
			"instances": [{"type": "t2.micro"}, {"type": "m1.small"}],
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"availabilityZones": ["ap-northeast-1a"],
			"mixedInstancesPolicy": {"launchTemplate": {"overrides": [{"instanceType": "t1.micro"}]}},
			"instances": [{"type": "m1.small"}],
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"availabilityZones": [
				"ap-northeast-1a",
				"ap-northeast-1c",
			],
			"mixedInstancesPolicy": {"launchTemplate": {"overrides": [{"instanceType": ""}]}},
			"instances": [{"type": "t1.micro"}],
		},
	]}}]}}
}

test_whether_instance_types_for_autoscaling_groups_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|ecs-test-ECSAutoScalingGroup-1BAGMH5EZ9ZCW",
				"displayName": "ecs-test-ECSAutoScalingGroup-1BAGMH5EZ9ZCW",
			},
			"availabilityZones": [
				"ap-northeast-1a",
				"ap-northeast-1c",
				"ap-northeast-1d",
			],
			"mixedInstancesPolicy": null,
			"instances": [{"type": "t2.micro"}],
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test",
				"displayName": "test",
			},
			"availabilityZones": ["ap-northeast-1a"],
			"mixedInstancesPolicy": {"launchTemplate": {"overrides": [{"instanceType": "m1.small"}]}},
			"instances": [{"type": "m1.small"}],
		},
	]}}]}}
}
