package policy.aws.codebuild.project_source_repository_credential

import data.shisho
import future.keywords

test_whether_credential_for_codebuild_project_source_repositories_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"source": {
				"type": "GITHUB",
				"auth": {
					"type": "OAUTH",
					"arn": "arn:aws:codebuild:ap-northeast-1:779397777777:token/github",
				},
			},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"source": {
				"type": "BITBUCKET",
				"auth": {
					"type": "OAUTH",
					"arn": "arn:aws:codebuild:ap-northeast-1:779397777777:token/bitbucket",
				},
			},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-3",
				"displayName": "test-project-3",
			},
			"source": {
				"type": "NO_SOURCE",
				"auth": null,
			},
		},
	]}}]}}
}

test_whether_credential_for_codebuild_project_source_repositories_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"source": {
				"type": "GITHUB",
				"auth": {
					"type": "BASIC_AUTH",
					"arn": "arn:aws:codebuild:ap-northeast-1:779397777777:token/github",
				},
			},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"source": {
				"type": "BITBUCKET",
				"auth": {
					"type": "PERSONAL_ACCESS_TOKEN",
					"arn": "arn:aws:codebuild:ap-northeast-1:779397777777:token/bitbucket",
				},
			},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-3",
				"displayName": "test-project-3",
			},
			"source": {
				"type": "NO_SOURCE",
				"auth": null,
			},
		},
	]}}]}}
}
