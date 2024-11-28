package policy.aws.ecr.repository_lifecycle_policy_config

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
			"lifecyclePolicy": {"policy": {"rawDocument": "{\"rules\":[{\"rulePriority\":1,\"description\":\"remove alpha images\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"sinceImagePushed\",\"countUnit\":\"days\",\"countNumber\":1},\"action\":{\"type\":\"expire\"}}]}"}},
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-2",
				"displayName": "test-repository-2",
			},
			"lifecyclePolicy": {"policy": {"rawDocument": "{\"rules\":[{\"rulePriority\":1,\"description\":\"remove alpha images\",\"selection\":{\"tagStatus\":\"any\",\"countType\":\"sinceImagePushed\",\"countUnit\":\"days\",\"countNumber\":1},\"action\":{\"type\":\"expire\"}}]}"}},
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
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-2",
				"displayName": "test-repository-2",
			},
			"lifecyclePolicy": null,
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-3",
				"displayName": "test-repository-3",
			},
			"lifecyclePolicy": {"policy": {"rawDocument": "{}"}},
		},
	]}}]}}
}
