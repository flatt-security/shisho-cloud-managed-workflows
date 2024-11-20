package policy.aws.s3.bucket_encryption

import data.shisho
import future.keywords

test_whether_the_bucket_encryption_is_enabled_for_aws_s3_buckets if {
	# check if the bucket encryption is enabled for AWS S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {"sseAlgorithm": "AES256"}}]},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {"sseAlgorithm": "AWS_KMS"}}]},
		},
	]}}]}}

	# Check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {"sseAlgorithm": "AES256"}}]},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {"sseAlgorithm": "INSECURE_ALGORITHM"}}]},
			"tags": [{"key": "foo", "value": "diff"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
