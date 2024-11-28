package policy.aws.s3.bucket_kms_encryption

import data.shisho
import future.keywords

test_whether_kms_encryption_is_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {
				"sseAlgorithm": "AWS_KMS",
				"kmsMasterKeyId": "arn:aws:kms:ap-northeast-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			}}]},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {
				"sseAlgorithm": "AWS_KMS_DSSE",
				"kmsMasterKeyId": "arn:aws:kms:ap-northeast-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			}}]},
		},
	]}}]}}
}

test_whether_kms_encryption_is_not_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {
				"sseAlgorithm": "AES256",
				"kmsMasterKeyId": "",
			}}]},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"encryptionConfiguration": {"rules": [{"encryptionByDefault": {
				"sseAlgorithm": "AWS_KMS",
				"kmsMasterKeyId": "",
			}}]},
		},
	]}}]}}
}
