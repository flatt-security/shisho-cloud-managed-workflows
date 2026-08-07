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

test_whether_instances_with_null_subnet_group_are_denied_and_others_are_judged if {
	results := [d | decisions[d]] with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|broken-null-subnet-group",
				"displayName": "broken-null-subnet-group",
			},
			"subnetGroup": null,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|healthy-in-vpc",
				"displayName": "healthy-in-vpc",
			},
			"subnetGroup": {"vpc": {"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00",
				"displayName": "vpc-0fb9667dee2b36e00",
			}}},
		},
	]}}]}}

	count(results) == 2
	count([d | d := results[_]; d.header.subject == "aws-rds-db-instance|ap-northeast-1|healthy-in-vpc"; shisho.decision.is_allowed(d)]) == 1
	count([d | d := results[_]; d.header.subject == "aws-rds-db-instance|ap-northeast-1|broken-null-subnet-group"; not shisho.decision.is_allowed(d)]) == 1
}

test_whether_instances_of_clusters_without_vpc_networking_are_excluded if {
	{s |
		decisions[d]
		s := d.header.subject
	} == {"aws-rds-db-instance|ap-northeast-1|vpc-cluster-instance-1"} with input as {"aws": {"accounts": [{"rds": {
		"clusters": [
			{"id": "express-cluster", "region": "ap-northeast-1", "vpcNetworkingEnabled": false},
			{"id": "vpc-cluster", "region": "ap-northeast-1", "vpcNetworkingEnabled": true},
		],
		"instances": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|express-cluster-instance-1",
					"displayName": "express-cluster-instance-1",
				},
				"clusterId": "express-cluster",
				"region": "ap-northeast-1",
				"subnetGroup": null,
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|vpc-cluster-instance-1",
					"displayName": "vpc-cluster-instance-1",
				},
				"clusterId": "vpc-cluster",
				"region": "ap-northeast-1",
				"subnetGroup": {"vpc": {"metadata": {
					"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00",
					"displayName": "vpc-0fb9667dee2b36e00",
				}}},
			},
		],
	}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"rds": {
		"clusters": [{"id": "vpc-cluster", "region": "ap-northeast-1", "vpcNetworkingEnabled": true}],
		"instances": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|vpc-cluster-instance-1",
					"displayName": "vpc-cluster-instance-1",
				},
				"clusterId": "vpc-cluster",
				"region": "ap-northeast-1",
				"subnetGroup": null,
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|standalone-1",
					"displayName": "standalone-1",
				},
				"clusterId": "",
				"region": "ap-northeast-1",
				"subnetGroup": null,
			},
		],
	}}]}}
}

test_whether_a_cluster_identifier_of_another_region_does_not_exclude_an_instance if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"rds": {
		"clusters": [
			{"id": "db-1", "region": "us-east-1", "vpcNetworkingEnabled": false},
			{"id": "db-1", "region": "ap-northeast-1", "vpcNetworkingEnabled": true},
		],
		"instances": [{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|db-1-instance-1",
				"displayName": "db-1-instance-1",
			},
			"clusterId": "db-1",
			"region": "ap-northeast-1",
			"subnetGroup": null,
		}],
	}}]}}
}
