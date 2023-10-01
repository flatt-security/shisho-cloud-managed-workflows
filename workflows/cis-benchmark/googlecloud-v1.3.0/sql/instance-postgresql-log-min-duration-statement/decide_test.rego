package policy.googlecloud.sql.instance_postgresql_log_min_duration_statement

import data.shisho
import future.keywords

test_whether_log_min_duration_statement_is_warning_for_postgresql_instances_of_cloud_sql if {
	# check if `log_min_duration_statement` is set to `-1` for all PostgreSQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-1",
				"displayName": "test-postgresql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "log_min_duration_statement",
				"value": "-1",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "log_min_duration_statement",
				"value": "-1",
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

	# check if `log_min_messages` is not set to `warning` for all PostgreSQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-1",
				"displayName": "test-postgresql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "log_min_duration_statement",
				"value": "20",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "log_min_duration_statement",
				"value": "30",
			}]},
		},
	]}}]}}
}
