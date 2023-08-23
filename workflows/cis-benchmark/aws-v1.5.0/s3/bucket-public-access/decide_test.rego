package policy.aws.s3.bucket_public_access_block

import data.shisho
import future.keywords

test_whether_the_public_access_is_blocked_for_aws_s3_buckets if {
	# check if the public access is blocked for AWS S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": true,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": true,
			},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": true,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": true,
			},
		},
	]}}]}}

	# check if the public access is not blocked for AWS S3 buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": false,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": false,
			},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": true,
				"ignorePublicAcls": false,
				"restrictPublicBuckets": true,
			},
		},
	]}}]}}

	# Check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": false,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": false,
			},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": true,
				"ignorePublicAcls": false,
				"restrictPublicBuckets": true,
			},
			"tags": [{"key": "foo", "value": "invalid"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
