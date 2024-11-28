package policy.aws.codebuild.project_logging_status

import data.shisho
import future.keywords

test_whether_logging_status_for_codebuild_projects_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"logsConfiguration": {"cloudWatchLogs": {
				"status": "ENABLED",
				"groupName": "test-group-1",
				"streamName": "test-log-stream-1",
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"logsConfiguration": {"s3Logs": {
				"location": "test-1",
				"status": "ENABLED",
			}},
		},
	]}}]}}
}

test_whether_logging_status_for_codebuild_projects_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"codeBuild": {"projects": [
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-1",
				"displayName": "test-project-1",
			},
			"logsConfiguration": {"cloudWatchLogs": {
				"status": "DISABLED",
				"groupName": "test-group-1",
				"streamName": "test-log-stream-1",
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"logsConfiguration": {"s3Logs": {
				"location": "test-1",
				"status": "DISABLED",
			}},
		},
		{
			"metadata": {
				"id": "aws-codebuild-project|ap-northeast-1|test-project-2",
				"displayName": "test-project-2",
			},
			"logsConfiguration": null,
		},
	]}}]}}
}
