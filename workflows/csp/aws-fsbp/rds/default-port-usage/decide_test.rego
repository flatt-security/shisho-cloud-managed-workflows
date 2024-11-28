package policy.aws.rds.default_port_usage

import data.shisho
import future.keywords

test_whether_default_port_of_rds_db_instances_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"aws": {"accounts": [{"rds": {
		"clusters": [
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|database-1",
					"displayName": "database-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 0,
			},
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|docdb-2023-06-28-12-28-51",
					"displayName": "docdb-2023-06-28-12-28-51",
				},
				"engine": "DOCDB",
				"port": 27017,
			},
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|test-aurora-mysql-1",
					"displayName": "test-aurora-mysql-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 0,
			},
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|test-neptune-cluster-1",
					"displayName": "test-neptune-cluster-1",
				},
				"engine": "NEPTUNE",
				"port": 8182,
			},
		],
		"instances": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|database-1-instance-1",
					"displayName": "database-1-instance-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 0,
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
					"displayName": "test-aurora-mysql-1-instance-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 0,
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
					"displayName": "test-mysql-1",
				},
				"engine": "MYSQL",
				"port": 0,
			},
		],
	}}]}}
}

test_whether_default_port_of_rds_db_instances_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 7 with input as {"aws": {"accounts": [{"rds": {
		"clusters": [
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|database-1",
					"displayName": "database-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 3306,
			},
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|docdb-2023-06-28-12-28-51",
					"displayName": "docdb-2023-06-28-12-28-51",
				},
				"engine": "SQLSERVER_EE",
				"port": 1433,
			},
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|test-aurora-mysql-1",
					"displayName": "test-aurora-mysql-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 3306,
			},
			{
				"metadata": {
					"id": "aws-rds-db-cluster|ap-northeast-1|test-neptune-cluster-1",
					"displayName": "test-neptune-cluster-1",
				},
				"engine": "ORACLE_EE",
				"port": 1521,
			},
		],
		"instances": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|database-1-instance-1",
					"displayName": "database-1-instance-1",
				},
				"engine": "AURORA_MYSQL",
				"port": 3306,
			},
			{},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
					"displayName": "test-aurora-mysql-1-instance-1",
				},
				"engine": "POSTGRES",
				"port": 5432,
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
					"displayName": "test-mysql-1",
				},
				"engine": "AURORA_POSTGRESQL",
				"port": 5432,
			},
			{},
		],
	}}]}}
}
