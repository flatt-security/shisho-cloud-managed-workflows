package policy.aws.rds.instance_accessibility

import data.shisho
import future.keywords

test_whether_rds_instances_are_publicly_accessible if {
	# check if RDS instances are publicly accessible
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"publiclyAccessible": false,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"publiclyAccessible": false,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestpostgres1"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
		},
	]}}]}}

	# check if RDS instances are not publicly accessible
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestpostgres1"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
		},
	]}}]}}

	# check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [
				{"routes": [
					{
						"gatewayId": "local",
						"destinationCidrBlock": "172.31.0.0/16",
					},
					{
						"gatewayId": "igw-0493d8c08ca6cb924",
						"destinationCidrBlock": "0.0.0.0/0",
					},
				]},
				{"routes": [{
					"gatewayId": "local",
					"destinationCidrBlock": "172.31.0.0/16",
				}]},
			]}},
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}

test_whether_instances_with_null_subnet_group_are_skipped_and_others_are_judged if {
	results := [d | decisions[d]] with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|broken-null-subnet-group"},
			"publiclyAccessible": true,
			"subnetGroup": null,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|healthy-private"},
			"publiclyAccessible": false,
			"subnetGroup": {"vpc": {"routeTables": []}},
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|healthy-public-igw"},
			"publiclyAccessible": true,
			"subnetGroup": {"vpc": {"routeTables": [{"routes": [{
				"gatewayId": "igw-0493d8c08ca6cb924",
				"destinationCidrBlock": "0.0.0.0/0",
			}]}]}},
		},
	]}}]}}

	count(results) == 2
	count([d | d := results[_]; d.header.subject == "aws-rds-db-instance|ap-northeast-1|healthy-private"; shisho.decision.is_allowed(d)]) == 1
	count([d | d := results[_]; d.header.subject == "aws-rds-db-instance|ap-northeast-1|healthy-public-igw"; not shisho.decision.is_allowed(d)]) == 1
	count([d | d := results[_]; d.header.subject == "aws-rds-db-instance|ap-northeast-1|broken-null-subnet-group"]) == 0
}
