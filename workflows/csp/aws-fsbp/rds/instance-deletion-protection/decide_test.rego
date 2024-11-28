package policy.aws.rds.instance_deletion_protection

import data.shisho
import future.keywords

test_deletion_protection_of_rds_db_instances_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"deletionProtection": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mariadb-1",
				"displayName": "test-mariadb-1",
			},
			"deletionProtection": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-postgres-1",
				"displayName": "test-postgres-1",
			},
			"deletionProtection": true,
		},
		{},
	]}}]}}
}

test_deletion_protection_of_rds_db_instances_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"deletionProtection": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mariadb-1",
				"displayName": "test-mariadb-1",
			},
			"deletionProtection": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-postgres-1",
				"displayName": "test-postgres-1",
			},
			"deletionProtection": false,
		},
		{},
	]}}]}}
}
