package policy.aws.cloudformation.stack_sns

import data.shisho
import future.keywords

test_whether_sns_topics_for_cloudformation_stacks_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFormation": {"stacks": [
		{
			"metadata": {
				"id": "bcb08e60-2f84-11ee-8b07-0ae657777777",
				"displayName": "test-stack-1",
			},
			"notificationArns": ["arn:aws:sns:ap-northeast-1:779397777777:test-notification-1"],
		},
		{
			"metadata": {
				"id": "96cbb310-2c72-11ee-8ad7-0665c",
				"displayName": "test-stack-2",
			},
			"notificationArns": ["arn:aws:sns:ap-northeast-1:779397777777:test-notification-2"],
		},
	]}}]}}
}

test_whether_sns_topics_for_cloudformation_stacks_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFormation": {"stacks": [
		{
			"metadata": {
				"id": "96cbb310-2c72-11ee-8ad7-0665c",
				"displayName": "test-stack-2",
			},
			"notificationArns": [],
		},
		{
			"metadata": {
				"id": "7e0c9170-e4e5-11ed-a4d7-065317777777",
				"displayName": "test-stack-3",
			},
			"notificationArns": [],
		},
	]}}]}}
}
