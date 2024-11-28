package policy.aws.rds.cluster_copy_tags_to_snapshots

import data.shisho
import future.keywords

test_copy_tags_to_snapshots_for_rds_clusters_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"copyTagsToSnapshot": true,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-2",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-2",
			},
			"copyTagsToSnapshot": true,
		},
		{
			"metadata": {
				"displayName": "docdb-2023-06-28-12-28-51",
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
			},
			"copyTagsToSnapshot": true,
		},
	]}}]}}
}

test_copy_tags_to_snapshots_for_rds_clusters_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"copyTagsToSnapshot": false,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-2",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-2",
			},
			"copyTagsToSnapshot": false,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-3",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-3",
			},
			"copyTagsToSnapshot": false,
		},
	]}}]}}
}
