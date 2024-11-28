package policy.aws.codebuild.project_env_variables

import data.shisho
import future.keywords

test_whether_env_variables_for_codebuild_projects_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"environment": {"environmentVariables": [{
				"type": "SECRETS_MANAGER",
				"name": "AWS_ACCESS_KEY_ID",
			}]},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"environment": {"environmentVariables": [{
				"type": "SECRETS_MANAGER",
				"name": "test_value_2",
			}]},
		},
	]}}]}}
}

test_whether_env_variables_for_codebuild_projects_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"environment": {"environmentVariables": [{
				"type": "PLAINTEXT",
				"name": "AWS_ACCESS_KEY_ID",
			}]},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"environment": {"environmentVariables": [{
				"type": "PLAINTEXT",
				"name": "TEST_PASSWORD",
			}]},
		},
	]}}]}}
}
