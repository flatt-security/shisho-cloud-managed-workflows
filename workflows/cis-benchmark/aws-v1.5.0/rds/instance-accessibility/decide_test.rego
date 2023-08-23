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
