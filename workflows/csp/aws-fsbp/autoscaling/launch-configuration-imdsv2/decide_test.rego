package policy.aws.autoscaling.launch_configuration_imdsv2

import data.shisho
import future.keywords

test_whether_imdsv2_for_autoscaling_groups_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"launchConfiguration": {"metadataOptions": {"httpTokens": "REQUIRED"}, "iamInstanceProfile": "non-empty"},
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"launchConfiguration": {"metadataOptions": {"httpTokens": "REQUIRED"}, "iamInstanceProfile": "non-empty"},
		},
	]}}]}}
}

test_whether_imdsv2_for_autoscaling_groups_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [{
		"metadata": {
			"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
			"displayName": "test-group-1",
		},
		"launchConfiguration": {"metadataOptions": {"httpTokens": "OPTIONAL"}, "iamInstanceProfile": "non-empty"},
	}]}}]}}
}
