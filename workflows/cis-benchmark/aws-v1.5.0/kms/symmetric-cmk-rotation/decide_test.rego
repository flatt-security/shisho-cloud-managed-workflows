package policy.aws.kms.symmetric_cmk_rotation

import data.shisho
import future.keywords

test_policy_rotation_for_symmetric_cmk_is_enabled if {
	# check if the rotation for symmetric CMKs is enabled
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"kms": {"keys": [
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|test-key-1",
				"displayName": "test-key-1",
			},
			"keyManager": "CUSTOMER",
			"keySpec": "SYMMETRIC_DEFAULT",
			"keyRotationEnabled": true,
		},
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|test-key-2",
				"displayName": "test-key-2",
			},
			"keyManager": "CUSTOMER",
			"keySpec": "SYMMETRIC_DEFAULT",
			"keyRotationEnabled": true,
		},
	]}}]}}

	# check if the rotation for symmetric CMKs is not enabled
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"kms": {"keys": [
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|test-key-1",
				"displayName": "test-key-1",
			},
			"keyManager": "CUSTOMER",
			"keySpec": "RSA_2048",
			"keyRotationEnabled": true,
		},
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|test-key-2",
				"displayName": "test-key-2",
			},
			"keyManager": "CUSTOMER",
			"keySpec": "SYMMETRIC_DEFAULT",
			"keyRotationEnabled": false,
		},
		{
			"metadata": {
				"id": "aws-kms-key|ap-northeast-1|test-key-3",
				"displayName": "test-key-3",
			},
			"keyManager": "AWS",
			"keySpec": "SYMMETRIC_DEFAULT",
			"keyRotationEnabled": true,
		},
	]}}]}}
}
