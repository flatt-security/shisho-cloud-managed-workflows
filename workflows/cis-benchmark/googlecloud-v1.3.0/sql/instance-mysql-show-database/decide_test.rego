package policy.googlecloud.sql.instance_mysql_show_database

import data.shisho
import future.keywords

test_whether_skip_show_database_is_off_for_mysql_instances_of_cloud_sql if {
	# check if `skip_show_database` is set to `on` for all MySQL instances of Google Cloud SQL
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
				"name": "skip_show_database",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-2",
				"displayName": "test-mysql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "skip_show_database",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-3",
				"displayName": "test-mysql-3",
			},
			"settings": {"databaseFlags": [{
				"name": "skip_show_database",
				"value": "on",
			}]},
		},
	]}}]}}

	# check if `skip_show_database` is not set to `on` for all MySQL instances of Google Cloud SQL
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
				"name": "skip_show_database",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-mysql-2",
				"displayName": "test-mysql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "skip_show_database",
				"value": "off",
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
