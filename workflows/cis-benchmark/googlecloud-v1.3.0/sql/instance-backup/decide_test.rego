package policy.googlecloud.sql.instance_backup

import data.shisho
import future.keywords

test_whether_proper_backup_is_enabled_for_cloud_sql if {
	# check if the backup is enabled for Google Cloud SQL instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-mysql-1"},
			"s1": {"backupConfiguration": {"enabled": true}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-1"},
			"s2": {"backupConfiguration": {"enabled": true}},
		},
	]}}]}}

	# check if the backup is enabled for Google Cloud SQL instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-mysql-1"},
			"s2": {"backupConfiguration": {"enabled": false}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-1"},
			"s1": {"backupConfiguration": {"enabled": false}},
		},
	]}}]}}
}
