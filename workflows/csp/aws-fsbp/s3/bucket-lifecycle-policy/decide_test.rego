package policy.aws.s3.bucket_lifecycle_policy

import data.shisho
import future.keywords

test_whether_bucket_lifecycle_policies_are_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-5",
				"displayName": "test-bucket-5",
			},
			"lifecycleConfiguration": {"rules": [{
				"id": "test-lifecycle-rule-1",
				"status": "ENABLED",
			}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"lifecycleConfiguration": {"rules": [{
				"id": "test-lifecycle-rule-2",
				"status": "ENABLED",
			}]},
		},
	]}}]}}
}

test_whether_bucket_lifecycle_policies_are_not_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-6",
				"displayName": "test-bucket-6",
			},
			"lifecycleConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-7",
				"displayName": "test-bucket-7",
			},
			"lifecycleConfiguration": {"rules": [{
				"id": "test-lifecycle-rule-4",
				"status": "DISABLED",
			}]},
		},
	]}}]}}
}
