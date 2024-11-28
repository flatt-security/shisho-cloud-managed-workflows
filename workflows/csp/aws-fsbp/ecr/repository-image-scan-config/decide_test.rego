package policy.aws.ecr.repository_image_scan_config

import data.shisho
import future.keywords

test_whether_image_scanning_for_ecr_repositories_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecr": {"repositories": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-1",
				"displayName": "test-repository-1",
			},
			"imageScanningConfiguration": {"scanOnPush": true},
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-2",
				"displayName": "test-repository-2",
			},
			"imageScanningConfiguration": {"scanOnPush": true},
		},
	]}}]}}
}

test_whether_image_scanning_for_ecr_repositories_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecr": {"repositories": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-1",
				"displayName": "test-repository-1",
			},
			"imageScanningConfiguration": {"scanOnPush": false},
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-2",
				"displayName": "test-repository-2",
			},
			"imageScanningConfiguration": {"scanOnPush": false},
		},
	]}}]}}
}
