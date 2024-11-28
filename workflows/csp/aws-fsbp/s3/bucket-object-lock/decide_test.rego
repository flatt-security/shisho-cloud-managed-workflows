package policy.aws.s3.bucket_object_lock

import data.shisho
import future.keywords

test_whether_object_lock_is_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-5",
				"displayName": "test-bucket-5",
			},
			"objectLockConfiguration": {"status": "ENABLED"},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"objectLockConfiguration": {"status": "ENABLED"},
		},
	]}}]}}
}

test_whether_object_lock_is_not_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-6",
				"displayName": "test-bucket-6",
			},
			"objectLockConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-7",
				"displayName": "test-bucket-7",
			},
			"objectLockConfiguration": {"status": "DISABLED"},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-8",
				"displayName": "test-bucket-8",
			},
			"objectLockConfiguration": {"status": "DISABLED"},
		},
	]}}]}}
}
