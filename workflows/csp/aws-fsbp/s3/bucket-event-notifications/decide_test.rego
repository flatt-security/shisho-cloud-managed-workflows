package policy.aws.s3.bucket_event_notifications

import data.shisho
import future.keywords

test_whether_event_notifications_are_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
				"displayName": "test-bucket-1",
			},
			"notificationConfiguration": {
				"eventBridgeConfiguration": {"enabled": true},
				"lambdaFunctionConfigurations": [{"arn": "arn:aws:lambda:ap-northeast-1:779392188153:function:test-function-1"}],
				"queueConfigurations": [],
				"topicConfigurations": [],
			},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"notificationConfiguration": {
				"eventBridgeConfiguration": {"enabled": true},
				"lambdaFunctionConfigurations": [],
				"queueConfigurations": [],
				"topicConfigurations": [],
			},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-3",
				"displayName": "test-bucket-3",
			},
			"notificationConfiguration": {
				"eventBridgeConfiguration": {"enabled": false},
				"lambdaFunctionConfigurations": [{"arn": "arn:aws:lambda:ap-northeast-1:779392188153:function:test-function-1"}],
				"queueConfigurations": [],
				"topicConfigurations": [],
			},
		},
	]}}]}}
}

test_whether_event_notifications_are_not_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
				"displayName": "test-bucket-1",
			},
			"notificationConfiguration": {
				"eventBridgeConfiguration": {"enabled": false},
				"lambdaFunctionConfigurations": [],
				"queueConfigurations": [],
				"topicConfigurations": [],
			},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"notificationConfiguration": {
				"eventBridgeConfiguration": {"enabled": false},
				"lambdaFunctionConfigurations": [],
				"queueConfigurations": [],
				"topicConfigurations": [],
			},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-3",
				"displayName": "test-bucket-3",
			},
			"notificationConfiguration": null,
		},
	]}}]}}
}
