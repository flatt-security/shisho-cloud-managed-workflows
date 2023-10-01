package policy.googlecloud.sql.instance_postgresql_log_connections

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := log_connections_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_postgresql_log_connections({
		"allowed": state == "on",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_log_connections_payload({"log_connections_state": state}),
	})
}

log_connections_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "log_connections"

	# the default is "off"
	flag.value == "on"
} else = "off"
