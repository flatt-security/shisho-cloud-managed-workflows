package policy.aws.codebuild.project_s3_logs_encryption

import data.shisho
import future.keywords

test_whether_s3_logs_encryption_for_codebuild_projects_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"logsConfiguration": {"s3Logs": {
				"location": "temp-1",
				"status": "ENABLED",
				"encryptionDisabled": false,
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"logsConfiguration": {"s3Logs": {
				"location": "temp-2",
				"status": "ENABLED",
				"encryptionDisabled": false,
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-3",
				"displayName": "test-project-3",
			},
			"logsConfiguration": null,
		},
	]}}]}}
}

test_whether_s3_logs_encryption_for_codebuild_projects_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"logsConfiguration": {"s3Logs": {
				"location": "temp-1",
				"status": "ENABLED",
				"encryptionDisabled": true,
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"logsConfiguration": {"s3Logs": {
				"location": "temp-2",
				"status": "ENABLED",
				"encryptionDisabled": true,
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-3",
				"displayName": "test-project-3",
			},
			"logsConfiguration": null,
		},
	]}}]}}
}
