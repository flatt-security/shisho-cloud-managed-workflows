package policy.aws.rds.instance_auto_upgrade

import data.shisho
import future.keywords

test_whether_auto_minor_version_upgrade_is_enabled_for_rds_instances if {
	# check if the auto minor version upgrade is enabled for RDS instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"autoMinorVersionUpgrade": true,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"autoMinorVersionUpgrade": true,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestpostgres1"},
			"autoMinorVersionUpgrade": true,
		},
	]}}]}}

	# check if the auto minor version upgrade is disabled for RDS instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"autoMinorVersionUpgrade": false,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"autoMinorVersionUpgrade": false,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestpostgres1"},
			"autoMinorVersionUpgrade": false,
		},
	]}}]}}

	# check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"autoMinorVersionUpgrade": false,
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"autoMinorVersionUpgrade": false,
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
