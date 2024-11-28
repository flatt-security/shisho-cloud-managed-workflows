package policy.aws.rds.cluster_administrator_username

import data.shisho
import future.keywords

test_administrator_username_of_rds_cluster_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|database-1",
				"displayName": "database-1",
			},
			"engine": "AURORA_MYSQL",
			"masterUsername": "admin123",
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"engine": "DOCDB",
			"masterUsername": "admin1234",
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
				"displayName": "test-aurora-mysql-1",
			},
			"engine": "AURORA",
			"masterUsername": "shisho-admin",
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1",
				"displayName": "test-neptune-cluster-1",
			},
			"engine": "NEPTUNE",
			"masterUsername": "shisho-admin",
		},
	]}}]}}
}

test_administrator_username_of_rds_cluster_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|database-1",
				"displayName": "database-1",
			},
			"engine": "AURORA_MYSQL",
			"masterUsername": "admin",
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"engine": "DOCDB",
			"masterUsername": "admin",
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
				"displayName": "test-aurora-mysql-1",
			},
			"engine": "AURORA",
			"masterUsername": "admin",
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-postgres-cluster-1",
				"displayName": "test-postgres-cluster-1",
			},
			"engine": "AURORA_POSTGRESQL",
			"masterUsername": "postgres",
		},
	]}}]}}
}
