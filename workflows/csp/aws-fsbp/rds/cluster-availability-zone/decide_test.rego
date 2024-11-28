package policy.aws.rds.cluster_availability_zone

import data.shisho
import future.keywords

test_multiple_availability_zones_of_rds_databases_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"multiAz": true,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-2",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-2",
			},
			"multiAz": true,
		},
		{
			"metadata": {
				"displayName": "docdb-2023-06-28-12-28-51",
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
			},
			"multiAz": true,
		},
	]}}]}}
}

test_multiple_availability_zones_of_rds_databases_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"clusters": [
		{
			"metadata": {
				"displayName": "test-aurora-mysql-1",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
			},
			"multiAz": false,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-2",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-2",
			},
			"multiAz": false,
		},
		{
			"metadata": {
				"displayName": "test-aurora-mysql-3",
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-3",
			},
			"multiAz": false,
		},
	]}}]}}
}
