package policy.aws.cloudtrail.cmk_encryption

import data.shisho
import future.keywords

test_whether_cloudtrail_is_encrypted_by_kms_cmk if {
	# check if the CloudTrail is encrypted by KMS CMK
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"kmsKeyId": "arn:aws:kms:ap-northeast-1:779392177777:key/6c7079dc-390c-4724-9e29-920317477777",
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"kmsKeyId": "arn:aws:kms:ap-northeast-1:779392177777:key/6c7079dc-390c-4724-9e29-920317488888",
		},
	]}}]}}

	# check if the CloudTrail is not encrypted by KMS CMK
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"kmsKeyId": "",
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"kmsKeyId": "",
		},
	]}}]}}
}
