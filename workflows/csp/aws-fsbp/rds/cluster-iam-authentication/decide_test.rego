package policy.aws.rds.cluster_iam_authentication

import data.shisho
import future.keywords

test_iam_authentication_of_rds_db_clusters_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "docdb-2023-06-28-12-28-51",
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
			},
			"iamDatabaseAuthenticationEnabled": true,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"iamDatabaseAuthenticationEnabled": true,
		},
		{
			"metadata": {
				"displayName": "test-neptune-cluster-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1",
			},
			"iamDatabaseAuthenticationEnabled": true,
		},
	]}}]}}
}

test_iam_authentication_of_rds_db_clusters_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "docdb-2023-06-28-12-28-51",
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
			},
			"iamDatabaseAuthenticationEnabled": false,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"iamDatabaseAuthenticationEnabled": false,
		},
		{
			"metadata": {
				"displayName": "test-neptune-cluster-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1",
			},
			"iamDatabaseAuthenticationEnabled": false,
		},
	]}}]}}
}
