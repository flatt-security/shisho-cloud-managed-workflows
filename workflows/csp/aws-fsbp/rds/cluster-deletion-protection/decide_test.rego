package policy.aws.rds.cluster_deletion_protection

import data.shisho
import future.keywords

test_deletion_protection_of_rds_clusters_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"engine": "docdb",
			"deletionProtection": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
				"displayName": "test-aurora-mysql-1",
			},
			"engine": "aurora-mysql",
			"deletionProtection": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1",
				"displayName": "test-neptune-cluster-1",
			},
			"engine": "neptune",
			"deletionProtection": true,
		},
	]}}]}}
}

test_deletion_protection_of_rds_clusters_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"engine": "docdb",
			"deletionProtection": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
				"displayName": "test-aurora-mysql-1",
			},
			"engine": "aurora-mysql",
			"deletionProtection": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1",
				"displayName": "test-neptune-cluster-1",
			},
			"engine": "neptune",
			"deletionProtection": false,
		},
	]}}]}}
}
