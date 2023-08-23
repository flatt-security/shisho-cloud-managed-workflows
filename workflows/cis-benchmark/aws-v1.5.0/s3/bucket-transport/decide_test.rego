package policy.aws.s3.bucket_transport

import data.shisho
import future.keywords

test_whether_the_bucket_transport_is_configured_properly_for_aws_s3_buckets if {
	# check if the bucket transport is configured properly for AWS S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294517777\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294517777\",\"Effect\":\"Deny\",\"Principal\":{\"Service\":\"logging.s3.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket-test-4/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294517777\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294517777\",\"Effect\":\"Deny\",\"Principal\":{\"Service\":\"logging.s3.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket-test-5/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":[\"false\"]}}}]}"},
		},
	]}}]}}

	# check if the bucket transport is configured properly for AWS S3 buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294517777\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294517777\",\"Effect\":\"Deny\",\"Principal\":{\"Service\":\"logging.s3.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket-test-4/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":[\"true\"]}}}]}"},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::test-bucket-3/*\",\"arn:aws:s3:::test-bucket-1\"]}]}"},
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-3"},
			"policy": {"rawDocument": ""},
		},
	]}}]}}

	# Check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1"},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294517777\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294517777\",\"Effect\":\"Deny\",\"Principal\":{\"Service\":\"logging.s3.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::bucket-test-4/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":[\"true\"]}}}]}"},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2"},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::test-bucket-3/*\",\"arn:aws:s3:::test-bucket-1\"]}]}"},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-3"},
			"policy": {"rawDocument": ""},
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
