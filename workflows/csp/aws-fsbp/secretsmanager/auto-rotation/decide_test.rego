package policy.aws.secretsmanager.auto_rotation

import data.shisho
import future.keywords

test_auto_rotation_for_secrets_manager_secrets_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"secretsManager": {"secrets": [
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-1",
				"displayName": "test-secret-1",
			},
			"rotationEnabled": true,
		},
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"rotationEnabled": true,
		},
	]}}]}}
}

test_auto_rotation_for_secrets_manager_secrets_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"secretsManager": {"secrets": [
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-1",
				"displayName": "test-secret-1",
			},
			"rotationEnabled": false,
		},
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"rotationEnabled": false,
		},
	]}}]}}
}
