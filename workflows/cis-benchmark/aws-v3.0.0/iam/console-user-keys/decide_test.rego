package policy.aws.iam.console_user_keys

import data.shisho
import future.keywords

test_whether_the_access_keys_are_not_enabled_for_user_who_has_password if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"iam": {
		"users": [
			{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBB"},
				"name": "test-user",
			},
			{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBC"},
				"name": "test-user-2",
			},
			{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBD"},
				"name": "test-user-3",
			},
			{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBE"},
				"name": "test-user-4",
			},
		],
		"credentialReport": {
			"metadata": {
				"id": "aws-iam-credential-report|77939277777",
				"displayName": "Report for 779392177777",
			},
			"contents": [
				{
					"user": "<root_account>",
					"passwordEnabled": false,
					"accessKey1Active": false,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": false,
					"accessKey2LastUsedAt": null,
				},
				# console user + used access key
				{
					"user": "test-user",
					"passwordEnabled": true,
					"accessKey1Active": false,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": true,
					"accessKey2LastUsedAt": "2023-01-01T00:00:00Z",
				},
				# console user + used  access key
				{
					"user": "test-user-2",
					"passwordEnabled": true,
					"accessKey1Active": true,
					"accessKey1LastUsedAt": "2023-01-01T00:00:00Z",
					"accessKey2Active": false,
					"accessKey2LastUsedAt": null,
				},
				# key-only user
				{
					"user": "test-user-3",
					"passwordEnabled": false,
					"accessKey1Active": true,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": false,
					"accessKey2LastUsedAt": null,
				},
				# key-only user
				{
					"user": "test-user-4",
					"passwordEnabled": false,
					"accessKey1Active": false,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": true,
					"accessKey2LastUsedAt": null,
				},
			],
		},
	}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {
		"users": [
			{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBB"},
				"name": "test-user",
			},
			{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBC"},
				"name": "test-user-2",
			},
		],
		"credentialReport": {
			"metadata": {
				"id": "aws-iam-credential-report|77939277777",
				"displayName": "Report for 779392177777",
			},
			"contents": [
				{
					"user": "<root_account>",
					"passwordEnabled": false,
					"accessKey1Active": false,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": false,
					"accessKey2LastUsedAt": null,
				},
				# console user + unused access key
				{
					"user": "test-user",
					"passwordEnabled": true,
					"accessKey1Active": false,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": true,
					"accessKey2LastUsedAt": null,
				},
				# console user + unused access key
				{
					"user": "test-user-2",
					"passwordEnabled": true,
					"accessKey1Active": true,
					"accessKey1LastUsedAt": null,
					"accessKey2Active": false,
					"accessKey2LastUsedAt": null,
				},
			],
		},
	}}]}}
}
