package policy.googlecloud.sql.instance_sqlserver_cross_db_ownership_chaining

import data.shisho
import future.keywords

test_whether_cross_db_ownership_chaining_is_off_for_sqlserver_instances_of_cloud_sql if {
	# check if `cross db ownership chaining` is set to `off` for all SQL Server instances of Google Cloud SQL
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-1",
				"displayName": "test-sqlserver-1",
			},
			"settings": {"databaseFlags": [{
				"name": "cross db ownership chaining",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-2",
				"displayName": "test-sqlserver-2",
			},
			"settings": {"databaseFlags": [{
				"name": "cross db ownership chaining",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-3",
				"displayName": "test-sqlserver-3",
			},
			"settings": {"databaseFlags": []},
		},
	]}}]}}

	# check if `cross db ownership chaining` is set to `off` for all SQL Server instances of Google Cloud SQL
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-1",
				"displayName": "test-sqlserver-1",
			},
			"settings": {"databaseFlags": [{
				"name": "cross db ownership chaining",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-2",
				"displayName": "test-sqlserver-2",
			},
			"settings": {"databaseFlags": [{
				"name": "cross db ownership chaining",
				"value": "on",
			}]},
		},
	]}}]}}
}
