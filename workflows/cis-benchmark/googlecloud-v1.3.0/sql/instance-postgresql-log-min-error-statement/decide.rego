package policy.googlecloud.sql.instance_postgresql_log_min_error_statement

import data.shisho

allowed_states := ["error"]

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := log_min_error_statement_state(instance.settings.databaseFlags)

	# available values are "debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error", "log", "fatal" and "panic" (see https://cloud.google.com/sql/docs/postgres/flags#postgres-l)
	# 1. `debug1 .. debug5` provides successively-more-detailed information for use by developers
	# 2. `info` provides information implicitly requested by the user, e.g., output from VACUUM VERBOSE
	# 3. `notice` provides information that might be helpful to users, e.g., notice of truncation of long identifiers
	# 4. `warning` provides warnings of likely problems, e.g., COMMIT outside a transaction block
	# 1. `error` reports an error that caused the current command to abort
	# 2. `log` reports information of interest to administrators, e.g., checkpoint activity
	# 3. `fatal` reports an error that caused the current session to abort
	# 4. `panic` reports an error that caused all database sessions to abort
	# the 'error' is recommended, but please update the `allowed_states` depending on your organization's logging policy such as `allowed_states := ["error", "warning"]`
	allowed := allowed_states[_] == state

	d := shisho.decision.googlecloud.sql.instance_postgresql_log_min_error_statement({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_log_min_error_statement_payload({"log_min_error_statement_state": state}),
	})
}

# the default value is "error"
log_min_error_statement_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "log_min_error_statement"
} else = "error"
