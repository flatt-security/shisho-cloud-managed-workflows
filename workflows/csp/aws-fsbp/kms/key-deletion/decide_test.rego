package policy.aws.kms.key_deletion

import data.shisho
import future.keywords

test_whether_deletion_state_for_kms_keys_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"kms": {"keys": [
		{
			"metadata": {
				"id": "aws-kms-key|us-east-1|318e4ced-9f1f-44c3-b2e2-86d0771c7777",
				"displayName": "318e4ced-9f1f-44c3-b2e2-86d0771c7777",
			},
			"keyManager": "CUSTOMER",
			"keyState": "ENABLED",
			"daletedAt": null,
		},
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|0acef6a5-e4ff-4837-989c-86d0771c7778",
				"displayName": "0acef6a5-e4ff-4837-989c-86d0771c7778",
			},
			"keyManager": "CUSTOMER",
			"keyState": "ENABLED",
			"daletedAt": null,
		},
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|0acef6a5-e4ff-4837-989c-86d0771c7779",
				"displayName": "0acef6a5-e4ff-4837-989c-86d0771c7779",
			},
			"keyManager": "AWS",
			"keyState": "ENABLED",
			"daletedAt": null,
		},
	]}}]}}
}

test_whether_deletion_state_for_kms_keys_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"kms": {"keys": [
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|a1255296-7fa6-4c14-ba41-86d0771c7777",
				"displayName": "a1255296-7fa6-4c14-ba41-86d0771c7777",
			},
			"keyManager": "CUSTOMER",
			"keyState": "PENDING_DELETION",
			"daletedAt": "2023-08-11T12:33:05Z",
		},
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|a1255296-7fa6-4c14-ba41-86d0771c7778",
				"displayName": "a1255296-7fa6-4c14-ba41-86d0771c7778",
			},
			"keyManager": "CUSTOMER",
			"keyState": "PENDING_DELETION",
			"daletedAt": "2023-08-24T12:33:05Z",
		},
	]}}]}}
}
