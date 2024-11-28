package policy.aws.ecr.repository_tag_immutability

import data.shisho
import future.keywords

test_whether_tag_immutability_for_ecr_repositories_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecr": {"repositories": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-1",
				"displayName": "test-repository-1",
			},
			"imageTagMutability": "IMMUTABLE",
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-2",
				"displayName": "test-repository-2",
			},
			"imageTagMutability": "IMMUTABLE",
		},
	]}}]}}
}

test_whether_tag_immutability_for_ecr_repositories_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecr": {"repositories": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-1",
				"displayName": "test-repository-1",
			},
			"imageTagMutability": "MUTABLE",
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|test-repository-2",
				"displayName": "test-repository-2",
			},
			"imageTagMutability": "MUTABLE",
		},
	]}}]}}
}
