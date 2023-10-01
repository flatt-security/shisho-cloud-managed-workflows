package policy.googlecloud.sql.instance_mysql_local_infile

import data.shisho
import future.keywords

test_whether_instance_mysql_local_infile_is_off_for_mysql_instances_of_cloud_sql if {
	# check if `local_infile` is set to `off` for all MySQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "local_infile",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-2",
				"displayName": "test-mysql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "local_infile",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-3",
				"displayName": "test-mysql-3",
			},
			"settings": {"databaseFlags": [{
				"name": "local_infile",
				"value": "off",
			}]},
		},
	]}}]}}

	# check if `local_infile` is not set to `off` for all MySQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "local_infile",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-2",
				"displayName": "test-mysql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "local_infile",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-3",
				"displayName": "test-mysql-3",
			},
			"settings": {"databaseFlags": []},
		},
	]}}]}}
}
