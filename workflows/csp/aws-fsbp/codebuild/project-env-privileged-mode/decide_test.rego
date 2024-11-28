package policy.aws.codebuild.project_env_privileged_mode

import data.shisho
import future.keywords

test_whether_env_privileged_mode_for_codebuild_projects_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"environment": {"privilegedMode": false},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"environment": {"privilegedMode": false},
		},
	]}}]}}
}

test_whether_env_privileged_mode_for_codebuild_projects_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"environment": {"privilegedMode": true},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"environment": {"privilegedMode": true},
		},
	]}}]}}
}
