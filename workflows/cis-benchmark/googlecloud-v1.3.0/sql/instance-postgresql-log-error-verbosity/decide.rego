package policy.googlecloud.sql.instance_postgresql_log_error_verbosity

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	allowed_states := ["default", "verbose"]
	state := log_error_verbosity_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_postgresql_log_error_verbosity({
		"allowed": allowed_states[_] == state,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_log_error_verbosity_payload({"log_error_verbosity_state": state}),
	})
}

# available values are "terse", "default" and "verbose" (see https://cloud.google.com/sql/docs/postgres/flags#postgres-l)
# 1. `default` logs the basic error information
# 2. `terse` excludes the logging of DETAIL, HINT, QUERY, and CONTEXT error information
# 3. `verbose` output includes the SQLSTATE error code and the source code file name, function name, and line number that generated the error
# the default value is "default" 
log_error_verbosity_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "log_error_verbosity"
} else = "default"
