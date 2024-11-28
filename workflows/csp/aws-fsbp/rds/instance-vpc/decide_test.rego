package policy.aws.rds.instance_vpc

import data.shisho
import future.keywords

test_whether_vpc_of_rds_db_instances_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"subnetGroup": {"vpc": {"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00",
				"displayName": "vpc-0fb9667dee2b36e00",
			}}},
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"subnetGroup": {"vpc": {"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00",
				"displayName": "vpc-0fb9667dee2b36e00",
			}}},
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1-instance-1",
				"displayName": "test-neptune-cluster-1-instance-1",
			},
			"subnetGroup": {"vpc": {"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00",
				"displayName": "vpc-0fb9667dee2b36e00",
			}}},
		},
	]}}]}}
}

test_whether_vpc_of_rds_db_instances_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|database-1-instance-1",
				"displayName": "database-1-instance-1",
			},
			"subnetGroup": {"vpc": null},
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"subnetGroup": null,
		},
	]}}]}}
}
