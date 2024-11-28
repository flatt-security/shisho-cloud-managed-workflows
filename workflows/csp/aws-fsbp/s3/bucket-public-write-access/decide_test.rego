package policy.aws.s3.bucket_public_write_access

import data.shisho
import future.keywords

test_whether_the_public_write_access_is_blocked_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-5",
				"displayName": "test-bucket-5",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": true,
			},
			"policy": {"rawDocument": "{}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "WRITE",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-6",
				"displayName": "test-bucket-6",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::test-bucket-6\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::test-bucket-6/AWSLogs/779392188153/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/test-trail-2\"}}}]}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-8",
				"displayName": "test-bucket-8",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294519317\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294519221\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::test-bucket-8/*\"}]}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-9",
				"displayName": "test-bucket-9",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": true,
			},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294519317\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294519221\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::test-bucket-8/*\"}]}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
	]}}]}}
}

test_whether_the_public_write_access_is_not_blocked_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-5",
				"displayName": "test-bucket-5",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "http://acs.amazonaws.com/groups/global/AllUsers",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "WRITE",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-6",
				"displayName": "test-bucket-6",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"AWSCloudTrailAclCheck20150319\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::test-bucket-6\",\"Condition\":{\"StringEquals\":{\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/test-trail-2\"}}},{\"Sid\":\"AWSCloudTrailWrite20150319\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::test-bucket-6/AWSLogs/779392188153/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"AWS:SourceArn\":\"arn:aws:cloudtrail:ap-northeast-1:779392188153:trail/test-trail-2\"}}}]}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-8",
				"displayName": "test-bucket-8",
			},
			"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
			},
			"policy": {"rawDocument": "{\"Version\":\"2012-10-17\",\"Id\":\"S3-Console-Auto-Gen-Policy-1679294519317\",\"Statement\":[{\"Sid\":\"S3PolicyStmt-DO-NOT-MODIFY-1679294519221\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"*:*\",\"Resource\":\"arn:aws:s3:::test-bucket-8/*\"}]}"},
			"aclGrants": [{
				"grantee": {
					"type": "CANONICAL_USER",
					"uri": "",
					"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1",
					"emailAddress": "",
					"displayName": "shisho-developers-notification+d01",
				},
				"permission": "FULL_CONTROL",
			}],
		},
	]}}]}}
}
