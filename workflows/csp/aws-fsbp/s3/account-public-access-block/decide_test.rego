package policy.aws.s3.account_public_access_block

import data.shisho
import future.keywords

test_whether_the_public_access_is_blocked_by_account_level_for_all_aws_s3_buckets if {
	# check if the public access is blocked by the account level for all AWS S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"s3": {"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": true,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": true,
			}},
		},
		{
			"metadata": {
				"id": "aws-account|779397777778",
				"displayName": "779397777778",
			},
			"s3": {"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": true,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": true,
			}},
		},
	]}}

	# check if the public access is not blocked by the account level for all AWS S3 buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"s3": {"publicAccessBlockConfiguration": {
				"blockPublicAcls": true,
				"blockPublicPolicy": false,
				"ignorePublicAcls": false,
				"restrictPublicBuckets": false,
			}},
		},
		{
			"metadata": {
				"id": "aws-account|779397777778",
				"displayName": "779397777778",
			},
			"s3": {"publicAccessBlockConfiguration": {
				"blockPublicAcls": false,
				"blockPublicPolicy": false,
				"ignorePublicAcls": true,
				"restrictPublicBuckets": true,
			}},
		},
		{
			"metadata": {
				"id": "aws-account|779397777779",
				"displayName": "779397777779",
			},
			"s3": {"publicAccessBlockConfiguration": null},
		},
	]}}
}
