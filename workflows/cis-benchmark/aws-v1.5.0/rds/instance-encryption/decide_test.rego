package policy.aws.rds.instance_encryption

import data.shisho
import future.keywords

test_whether_storage_encryption_is_enabled_for_rds_instances if {
	# check if the storage encryption is enabled for RDS instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"storageEncrypted": true,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"storageEncrypted": true,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestpostgres1"},
			"storageEncrypted": true,
		},
	]}}]}}

	# check if storage encryption is disabled for RDS instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-1-instance-1"},
			"storageEncrypted": false,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestmysql1"},
			"storageEncrypted": false,
		},
		{
			"metadata": {"id": "aws-rds-db-instance|ap-northeast-1|tftestpostgres1"},
			"storageEncrypted": false,
		},
	]}}]}}
}
