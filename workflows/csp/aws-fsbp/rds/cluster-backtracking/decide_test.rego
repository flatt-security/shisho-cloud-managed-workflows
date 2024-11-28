package policy.aws.rds.cluster_backtracking

import data.shisho
import future.keywords

test_backtracking_of_rds_clusters_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"engine": "AURORA_MYSQL",
			"backtrackWindow": 3600,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-2",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-2",
			},
			"engine": "AURORA_MYSQL",
			"backtrackWindow": 3600,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-3",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-3",
			},
			"engine": "AURORA_MYSQL",
			"backtrackWindow": 10800,
		},
		{
			"metadata": {
				"displayName": "docdb-2023-06-28-12-28-51",
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
			},
			"engine": "DOCDB",
			"backtrackWindow": 0,
		},
	]}}]}}
}

test_backtracking_of_rds_clusters_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"engine": "AURORA_MYSQL",
			"backtrackWindow": 0,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-2",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-2",
			},
			"engine": "AURORA_MYSQL",
			"backtrackWindow": 0,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-3",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-3",
			},
			"engine": "AURORA_MYSQL",
			"backtrackWindow": 0,
		},
		{
			"metadata": {
				"displayName": "docdb-2023-06-28-12-28-51",
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
			},
			"engine": "DOCDB",
			"backtrackWindow": 0,
		},
	]}}]}}
}
