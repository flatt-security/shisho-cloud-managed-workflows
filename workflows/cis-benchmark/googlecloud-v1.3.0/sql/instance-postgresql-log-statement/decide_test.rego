package policy.googlecloud.sql.instance_postgresql_log_statement

import data.shisho
import future.keywords

test_whether_log_statement_is_none_for_postgresql_instances_of_cloud_sql if {
	# check if `log_statement` is set to `ddl` for all PostgreSQL instances of Google Cloud SQL
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
				"name": "log_statement",
				"value": "ddl",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "log_statement",
				"value": "ddl",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-3",
				"displayName": "test-postgresql-3",
			},
			"settings": {"databaseFlags": [{
				"name": "log_statement",
				"value": "ddl",
			}]},
		},
	]}}]}}

	# check if `log_statement` is not set to `ddl` for all PostgreSQL instances of Google Cloud SQL
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-1",
				"displayName": "test-postgresql-1",
			},
			"settings": {"databaseFlags": [{
				"name": "log_statement",
				"value": "none",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "log_statement",
				"value": "all",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-3",
				"displayName": "test-postgresql-3",
			},
			"settings": {"databaseFlags": []},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-4",
				"displayName": "test-postgresql-4",
			},
			"settings": {"databaseFlags": [{
				"name": "log_statement",
				"value": "mod",
			}]},
		},
	]}}]}}
}
