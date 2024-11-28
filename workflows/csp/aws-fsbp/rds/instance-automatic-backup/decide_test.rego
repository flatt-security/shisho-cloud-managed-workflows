package policy.aws.rds.instance_automatic_backup

import data.shisho
import future.keywords

test_automatic_backup_of_rds_db_instances_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"backupRetentionPeriod": 10,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"backupRetentionPeriod": 15,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-1",
				"displayName": "test-mysql-1-instance-1",
			},
			"backupRetentionPeriod": 7,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-2",
				"displayName": "test-mysql-1-instance-2",
			},
			"backupRetentionPeriod": 7,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-3",
				"displayName": "test-mysql-1-instance-3",
			},
			"backupRetentionPeriod": 7,
		},
	]}}]}}
}

test_automatic_backup_of_rds_db_instances_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 5 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"backupRetentionPeriod": 1,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"backupRetentionPeriod": 5,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-1",
				"displayName": "test-mysql-1-instance-1",
			},
			"backupRetentionPeriod": 3,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-2",
				"displayName": "test-mysql-1-instance-2",
			},
			"backupRetentionPeriod": 3,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-3",
				"displayName": "test-mysql-1-instance-3",
			},
			"backupRetentionPeriod": 3,
		},
	]}}]}}
}
