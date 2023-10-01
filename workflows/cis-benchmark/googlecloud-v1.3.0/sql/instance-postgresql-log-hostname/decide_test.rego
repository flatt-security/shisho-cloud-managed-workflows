package policy.googlecloud.sql.instance_postgresql_centralized_logging

import data.shisho
import future.keywords

test_whether_cloudsql_enable_pgaudit_is_on_for_postgresql_instances_of_cloud_sql if {
	# check if `cloudsql.enable_pgaudit` is set to `on` for all PostgreSQL instances of Google Cloud SQL
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
				"name": "cloudsql.enable_pgaudit",
				"value": "on",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "cloudsql.enable_pgaudit",
				"value": "on",
			}]},
		},
	]}}]}}

	# check if `cloudsql.enable_pgaudit` is not set to `on` for all PostgreSQL instances of Google Cloud SQL
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
				"name": "cloudsql.enable_pgaudit",
				"value": "off",
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-sql-instance|514897777777|test-postgresql-2",
				"displayName": "test-postgresql-2",
			},
			"settings": {"databaseFlags": [{
				"name": "cloudsql.enable_pgaudit",
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
