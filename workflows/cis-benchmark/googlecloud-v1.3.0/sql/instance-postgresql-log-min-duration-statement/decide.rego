package policy.googlecloud.sql.instance_postgresql_log_min_duration_statement

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	ms := log_min_duration_statement(instance.settings.databaseFlags)

	# the range: -1 - 2147483647 ms
	# the default value: -1
	allowed := ms == -1

	d := shisho.decision.googlecloud.sql.instance_postgresql_log_min_duration_statement({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_log_min_duration_statement_payload({"milliseconds_of_log_min_duration_statement": ms}),
	})
}

log_min_duration_statement(database_flags) := x {
	flag := database_flags[_]
	flag.name == "log_min_duration_statement"
	x := to_number(flag.value)
} else = -1
