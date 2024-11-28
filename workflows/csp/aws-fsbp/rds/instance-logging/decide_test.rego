package policy.aws.rds.instance_logging

import data.shisho
import future.keywords

test_logging_of_rds_db_instances_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"engine": "POSTGRES",
			"enabledCloudwatchLogsExports": [
				"upgrade",
				"postgresql",
			],
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"engine": "MYSQL",
			"enabledCloudwatchLogsExports": [
				"slowquery",
				"error",
				"general",
				"audit",
			],
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-oracle-1",
				"displayName": "test-oracle-1",
			},
			"engine": "ORACLE_EE",
			"enabledCloudwatchLogsExports": [
				"audit",
				"alert",
				"trace",
				"listener",
			],
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-sqlserver-1",
				"displayName": "test-sqlserver-1",
			},
			"engine": "SQLSERVER_EE",
			"enabledCloudwatchLogsExports": [
				"agent",
				"error",
			],
		},
	]}}]}}
}

test_logging_of_rds_db_instances_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"engine": "POSTGRES",
			"enabledCloudwatchLogsExports": ["upgrade"],
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"engine": "MYSQL",
			"enabledCloudwatchLogsExports": [
				"slowquery",
				"error",
				"audit",
			],
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-oracle-1",
				"displayName": "test-oracle-1",
			},
			"engine": "ORACLE_EE",
			"enabledCloudwatchLogsExports": [
				"audit",
				"alert",
				"listener",
			],
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-sqlserver-1",
				"displayName": "test-sqlserver-1",
			},
			"engine": "SQLSERVER_EE",
			"enabledCloudwatchLogsExports": ["error"],
		},
	]}}]}}
}
