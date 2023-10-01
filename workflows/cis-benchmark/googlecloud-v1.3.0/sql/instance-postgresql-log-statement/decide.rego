package policy.googlecloud.sql.instance_postgresql_log_statement

import data.shisho

allowed_states := ["ddl"]

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := log_statement_state(instance.settings.databaseFlags)

	# available values are "none", "ddl", "mod" and "all" (see https://cloud.google.com/sql/docs/postgres/flags#postgres-l)
	# 1. `all` logs all statements
	# 2. `ddl` logs all data definition statements, such as CREATE, ALTER, and DROP statements
	# 3. `mod` logs all ddl statements, plus data-modifying statements such as INSERT, UPDATE, DELETE, TRUNCATE, and COPY FROM. PREPARE, EXECUTE, and EXPLAIN ANALYZE statements are also logged if their contained command is of an appropriate type
	# 4. `none` does not log any statements
	# the 'ddl' is recommended, but please update the `allowed_states` depending on your organization's logging policy such as `allowed_states := ["ddl", "mod", "all"]`
	allowed := state == allowed_states[_]

	d := shisho.decision.googlecloud.sql.instance_postgresql_log_statement({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_log_statement_payload({"log_statement_state": state}),
	})
}

# the default value is "none"
log_statement_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "log_statement"
} else = "none"
