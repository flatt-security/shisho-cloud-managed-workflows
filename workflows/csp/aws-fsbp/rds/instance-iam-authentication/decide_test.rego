package policy.aws.rds.instance_iam_authentication

import data.shisho
import future.keywords

test_iam_authentication_of_rds_db_instances_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"iamDatabaseAuthenticationEnabled": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"iamDatabaseAuthenticationEnabled": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-1",
				"displayName": "test-mysql-1-instance-1",
			},
			"iamDatabaseAuthenticationEnabled": true,
		},
	]}}]}}
}

test_iam_authentication_of_rds_db_instances_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"iamDatabaseAuthenticationEnabled": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"iamDatabaseAuthenticationEnabled": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1-instance-1",
				"displayName": "test-mysql-1-instance-1",
			},
			"iamDatabaseAuthenticationEnabled": false,
		},
	]}}]}}
}
