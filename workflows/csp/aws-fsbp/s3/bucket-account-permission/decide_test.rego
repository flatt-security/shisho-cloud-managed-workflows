package policy.aws.s3.bucket_account_permission

import data.shisho
import future.keywords

test_whether_other_account_permission_is_denied_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{
		"id": "779399999999",
		"s3": {"buckets": [
			{
				"metadata": {
					"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
					"displayName": "test-bucket-1",
				},
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::test-bucket-5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/test-logging-1\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::test-bucket-5/AWSLogs/779392188153/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":false}}}]}"},
			},
			{
				"metadata": {
					"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
					"displayName": "test-bucket-2",
				},
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::779399999999:root\"},\"Action\":\"s3:PutEncryptionConfiguration\",\"Resource\":\"arn:aws:s3:::test-bucket-2\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/tier1-4.8-test\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::test-bucket-2/AWSLogs/779392188153/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/tier1-4.8-test\"}}}]}"},
			},
			{
				"metadata": {
					"id": "aws-s3-bucket|ap-northeast-1|test-bucket-3",
					"displayName": "test-bucket-3",
				},
				"policy": {"rawDocument": ""},
			},
			{
				"metadata": {
					"id": "aws-s3-bucket|ap-northeast-1|test-bucket-4",
					"displayName": "test-bucket-4",
				},
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::tf-test-s3-bucket/*\",\"arn:aws:s3:::tf-test-s3-bucket\"]}]}"},
			},
		]},
	}]}}
}

test_whether_other_account_permission_is_allowed_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{
		"id": "779399999999",
		"s3": {"buckets": [
			{
				"metadata": {
					"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
					"displayName": "test-bucket-1",
				},
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:DeleteBucketPolicy\",\"Resource\":\"arn:aws:s3:::test-bucket-5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/test-logging-1\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::test-bucket-5/AWSLogs/779392188153/*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":false}}}]}"},
			},
			{
				"metadata": {
					"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
					"displayName": "test-bucket-2",
				},
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"s3:PutEncryptionConfiguration\",\"Resource\":\"arn:aws:s3:::test-bucket-2\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/tier1-4.8-test\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::test-bucket-2/AWSLogs/779392188153/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/tier1-4.8-test\"}}}]}"},
			},
		]},
	}]}}
}
