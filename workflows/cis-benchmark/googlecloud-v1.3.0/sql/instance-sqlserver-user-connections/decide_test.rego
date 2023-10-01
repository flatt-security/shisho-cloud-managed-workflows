package policy.googlecloud.sql.instance_sqlserver_user_connections

import data.shisho
import future.keywords

test_whether_user_connections_is_zero_for_sqlserver_instances_of_cloud_sql if {
	# check if `user connections` is set to 0 for all SQL Server instances of Google Cloud SQL
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
				"name": "user connections",
				"value": "0",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-2",
				"displayName": "test-sqlserver-2",
			},
			"settings": {"databaseFlags": [{
				"name": "user connections",
				"value": "0",
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

	# check if `user connections` is set to 0 for all SQL Server instances of Google Cloud SQL
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
				"name": "user connections",
				"value": "10",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-sqlserver-2",
				"displayName": "test-sqlserver-2",
			},
			"settings": {"databaseFlags": [{
				"name": "user connections",
				"value": "200",
			}]},
		},
	]}}]}}
}
