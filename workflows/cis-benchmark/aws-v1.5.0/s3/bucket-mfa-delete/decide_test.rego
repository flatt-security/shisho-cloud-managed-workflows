package policy.aws.s3.bucket_mfa_delete

import data.shisho
import future.keywords

test_whether_the_mfa_delete_is_enabled_for_aws_s3_buckets if {
	# check if the bucket MFA Delete is enabled for AWS S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"versioning": {
				"mfaDelete": "ENABLED",
				"status": "ENABLED",
			},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"versioning": {
				"mfaDelete": "ENABLED",
				"status": "ENABLED",
			},
		},
	]}}]}}

	# check if the bucket MFA Delete is disabled for AWS S3 buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"versioning": {
				"mfaDelete": "ENABLED",
				"status": "DISABLED",
			},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"versioning": {
				"mfaDelete": "DISABLED",
				"status": "ENABLED",
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
			"versioning": {
				"mfaDelete": "ENABLED",
				"status": "DISABLED",
			},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"versioning": {
				"mfaDelete": "DISABLED",
				"status": "ENABLED",
			},
			"tags": [{"key": "foo", "value": "invalid"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
