package policy.aws.s3.bucket_access_logging

import data.shisho
import future.keywords

test_whether_the_access_logging_is_enabled_for_aws_s3_buckets if {
	# check if the access logging is enabled for AWS S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"logging": {
				"targetBucket": "test-bucket-2",
				"targetPrefix": "",
			},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"logging": {
				"targetBucket": "test-bucket-1",
				"targetPrefix": "",
			},
		},
	]}}]}}

	# check if the access logging is disabled for AWS S3 buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|shisho-cloud-tfstate-1"},
			"logging": null,
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|tf-test-s3-bucket"},
			"logging": null,
		},
	]}}]}}

	# Check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|shisho-cloud-tfstate-1"},
			"logging": null,
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|tf-test-s3-bucket"},
			"logging": null,
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
