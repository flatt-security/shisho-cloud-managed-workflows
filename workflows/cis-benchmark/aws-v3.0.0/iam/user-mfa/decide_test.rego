package policy.aws.iam.user_mfa

import data.shisho
import future.keywords

test_whether_the_mfa_is_enabled_for_user_who_has_password if {
	# check if the MFA is enabled for the user who has password
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
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
					"mfaActive": false,
				},
				{
					"user": "test-user",
					"passwordEnabled": true,
					"mfaActive": true,
				},
				{
					"user": "test-user-2",
					"passwordEnabled": true,
					"mfaActive": true,
				},
			],
		},
	}}]}}

	# check if the MFA is enabled for the user who has password
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{"iam": {
			"users": [{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBD"},
				"name": "test-user",
			}],
			"credentialReport": {
				"metadata": {
					"id": "aws-iam-credential-report|77939277777",
					"displayName": "Report for 779392177777",
				},
				"contents": [
					{
						"user": "<root_account>",
						"passwordEnabled": false,
						"mfaActive": false,
					},
					{
						"user": "test-user",
						"passwordEnabled": true,
						"mfaActive": false,
					},
				],
			},
		}},
		{"iam": {
			"users": [{
				"metadata": {"id": "aws-iam-user|AIDA3K53E734T6EZBBBE"},
				"name": "test-user",
			}],
			"credentialReport": {
				"metadata": {
					"id": "aws-iam-credential-report|77939288888",
					"displayName": "Report for 779392188888",
				},
				"contents": [
					{
						"user": "<root_account>",
						"passwordEnabled": false,
						"mfaActive": false,
					},
					{
						"user": "test-user",
						"passwordEnabled": true,
						"mfaActive": false,
					},
				],
			},
		}},
	]}}
}
