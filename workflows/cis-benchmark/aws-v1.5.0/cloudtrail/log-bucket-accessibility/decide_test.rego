package policy.aws.cloudtrail.log_bucket_accessibility

import data.shisho
import future.keywords

test_whether_s3_bucket_for_cloudtrail_is_not_publicly_accessible if {
	# check if the S3 bucket for CloudTrail is not publicly accessible
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6677777",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d01",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-1\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-1\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d02",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-3",
				"displayName": "test-trail-3",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d03",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-4",
				"displayName": "test-trail-4",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d04",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-5",
				"displayName": "test-trail-5",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-6",
				"displayName": "test-trail-6",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d04",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": "{}",
			},
		},
	]}}]}}

	# check if the S3 bucket for CloudTrail is publicly accessible by ACL grants
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6677777",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d01",
						"uri": "https://acs.amazonaws.com/groups/global/AllUsers",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-1\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-1\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d02",
						"uri": "https://acs.amazonaws.com/groups/global/AuthenticatedUsers",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
	]}}]}}

	# check if the S3 bucket for CloudTrail is publicly accessible by a bucket policy
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6677777",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d01",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-1\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-1\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"s3Bucket": {
				"name": "aws-cloudtrail-logs-779392188153-b6688888",
				"aclGrants": [{
					"grantee": {
						"displayName": "test-grantee+d02",
						"uri": "",
					},
					"permission": "FULL_CONTROL",
				}],
				"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779392188153-b669bfe5\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::aws-cloudtrail-logs-779397777777-b669bfe5/AWSLogs/779397777777/*\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779397777777:trail/test-trail-2\",\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}}]}"},
			},
		},
	]}}]}}
}
