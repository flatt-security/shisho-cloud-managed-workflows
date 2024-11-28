package policy.aws.rds.instance_availability_zone

import data.shisho
import future.keywords

test_multiple_availability_zones_of_rds_databases_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"multiAz": true,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mariadb-1",
				"displayName": "test-mariadb-1",
			},
			"multiAz": true,
		},
		{},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-postgres-1",
				"displayName": "test-postgres-1",
			},
			"multiAz": true,
		},
	]}}]}}
}

test_multiple_availability_zones_of_rds_databases_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"multiAz": false,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mariadb-1",
				"displayName": "test-mariadb-1",
			},
			"multiAz": false,
		},
		{},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-postgres-1",
				"displayName": "test-postgres-1",
			},
			"multiAz": false,
		},
	]}}]}}
}
