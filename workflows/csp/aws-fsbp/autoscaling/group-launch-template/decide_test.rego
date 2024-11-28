package policy.aws.autoscaling.group_launch_template

import data.shisho
import future.keywords

test_whether_launch_template_for_autoscaling_instances_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		# Both of mixedInstancePolicy and per-instance launchTemplate are set
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-template-3",
				"displayName": "test-template-3",
			},
			"mixedInstancesPolicy": {"launchTemplate": {"specification": {
				"id": "lt-0f1d0074589ad91b4",
				"name": "test-template-2",
				"number": "$Default",
			}}},
			"launchConfiguration": null,
			"instances": [{"launchTemplate": {
				"id": "lt-0f1d0074589ad91b4",
				"name": "test-template-2",
				"number": 3,
			}}],
		},
		# Only per-instance launchTemplate is set
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"mixedInstancesPolicy": null,
			"launchConfiguration": null,
			"instances": [{"launchTemplate": {
				"id": "lt-0f1d0074589ad91b4",
				"name": "test-template-2",
				"number": 1,
			}}],
		},
		# Only mixedInstancePolicy is set
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-template-4",
				"displayName": "test-template-4",
			},
			"mixedInstancesPolicy": {"launchTemplate": {"specification": {
				"id": "lt-0f1d0074589ad91b4",
				"name": "test-template-2",
				"number": 1,
			}}},
			"launchConfiguration": null,
			"instances": [{"launchTemplate": null}],
		},
	]}}]}}
}

test_whether_launch_template_for_autoscaling_instances_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-template-3",
				"displayName": "test-template-3",
			},
			"mixedInstancesPolicy": null,
			"launchConfiguration": {"imageId": "ami-02265963d1614d04d"},
			"instances": [{"launchTemplate": null}],
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-template-4",
				"displayName": "test-template-4",
			},
			"mixedInstancesPolicy": null,
			"launchConfiguration": {"imageId": "ami-02265963d1614d05f"},
			"instances": [{"launchTemplate": null}],
		},
	]}}]}}
}
