package policy.aws.s3.bucket_acl

import data.shisho
import future.keywords

test_whether_acl_is_not_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
				"displayName": "test-bucket-1",
			},
			"aclGrants": [{"grantee": {"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1"}}],
			"ownershipControls": {"rules": [{"objectOwnership": "BUCKET_OWNER_ENFORCED"}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"aclGrants": [],
			"ownershipControls": {"rules": [{"objectOwnership": "BUCKET_OWNER_ENFORCED"}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-3",
				"displayName": "test-bucket-3",
			},
			"aclGrants": [],
			"ownershipControls": {"rules": [{"objectOwnership": "BUCKET_OWNER_PREFERRED"}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-4",
				"displayName": "test-bucket-4",
			},
			"aclGrants": [],
			"ownershipControls": null,
		},
	]}}]}}
}

test_whether_acl_is_enabled_for_aws_s3_buckets if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"s3": {"buckets": [
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-1",
				"displayName": "test-bucket-1",
			},
			"aclGrants": [{"grantee": {"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f1"}}],
			"ownershipControls": {"rules": [{"objectOwnership": "BUCKET_OWNER_PREFERRED"}]},
		},
		{
			"metadata": {
				"id": "aws-s3-bucket|ap-northeast-1|test-bucket-2",
				"displayName": "test-bucket-2",
			},
			"aclGrants": [{"grantee": {"id": "b60b86f24bbf3110d82adee9493745597a90d03d879380f370e7a62f2ce7f9f2"}}],
			"ownershipControls": {"rules": [{"objectOwnership": "BUCKET_OWNER_PREFERRED"}]},
		},
	]}}]}}
}
