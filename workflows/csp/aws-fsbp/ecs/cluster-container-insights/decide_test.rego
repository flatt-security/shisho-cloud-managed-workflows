package policy.aws.ecs.cluster_container_insights

import data.shisho
import future.keywords

test_container_insights_for_clusters_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{
			"metadata": {
				"id": "aws-ecs-cluster|ap-northeast-1|test-cluster-1",
				"displayName": "test-cluster-1",
			},
			"settings": [{
				"name": "CONTAINERINSIGHTS",
				"value": "enabled",
			}],
		},
		{
			"metadata": {
				"id": "aws-ecs-cluster|ap-northeast-1|test-cluster-2",
				"displayName": "test-cluster-2",
			},
			"settings": [{
				"name": "CONTAINERINSIGHTS",
				"value": "enabled",
			}],
		},
	]}}]}}
}

test_container_insights_for_clusters_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{
			"metadata": {
				"id": "aws-ecs-cluster|ap-northeast-1|test-cluster-3",
				"displayName": "test-cluster-3",
			},
			"settings": [{
				"name": "CONTAINERINSIGHTS",
				"value": "disabled",
			}],
		},
		{
			"metadata": {
				"id": "aws-ecs-cluster|ap-northeast-1|test-cluster-4",
				"displayName": "test-cluster-4",
			},
			"settings": [{
				"name": "CONTAINERINSIGHTS",
				"value": "disabled",
			}],
		},
		{
			"metadata": {
				"id": "aws-ecs-cluster|ap-northeast-1|test-cluster-5",
				"displayName": "test-cluster-5",
			},
			"settings": [],
		},
	]}}]}}
}
