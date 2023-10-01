package policy.googlecloud.sql.instance_postgresql_log_disconnections

import data.shisho
import future.keywords

test_whether_log_connections_is_off_for_postgresql_instances_of_cloud_sql if {
	# check if `log_disconnections` is set to `on` for all PostgreSQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-1",
				"displayName": "test-postgresql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "log_disconnections",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "log_disconnections",
				"value": "on",
			}]},
		},
	]}}]}}

	# check if `log_disconnections` is not set to `on` for all PostgreSQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-1",
				"displayName": "test-postgresql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "log_disconnections",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "log_disconnections",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-3",
				"displayName": "test-postgresql-3",
			},
			"settings": {"databaseFlags": []},
		},
	]}}]}}
}
