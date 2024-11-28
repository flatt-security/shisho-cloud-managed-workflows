package policy.aws.s3.bucket_cross_region_replication

import data.shisho
import future.keywords

test_whether_cross_region_replication_is_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
				"displayName": "test-bucket-1",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": {"rules": [{
				"status": "ENABLED",
				"destination": {"bucket": "arn:aws:s3:::test-osaka-region-bucket-1"},
			}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-3|test-bucket-for-web-hosting-4",
				"displayName": "test-bucket-for-web-hosting-4",
			},
			"region": "ap-northeast-3",
			"replicationConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-2|test-osaka-region-bucket-1",
				"displayName": "test-osaka-region-bucket-1",
			},
			"region": "ap-northeast-2",
			"replicationConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-3",
				"displayName": "test-bucket-3",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": {"rules": [{
				"status": "ENABLED",
				"destination": {"bucket": "arn:aws:s3:::test-bucket-for-web-hosting-4"},
			}]},
		},
	]}}]}}
}

test_whether_cross_region_replication_is_not_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
				"displayName": "test-bucket-1",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": {"rules": [{
				"status": "ENABLED",
				"destination": {"bucket": "arn:aws:s3:::test-osaka-region-bucket-1"},
			}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-3",
				"displayName": "test-bucket-3",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-osaka-region-bucket-1",
				"displayName": "test-osaka-region-bucket-1",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-4",
				"displayName": "test-bucket-4",
			},
			"region": "ap-northeast-1",
			"replicationConfiguration": {"rules": [{
				"status": "ENABLED",
				"destination": {"bucket": "arn:aws:s3:::test-bucket-3"},
			}]},
		},
	]}}]}}
}
