package policy.googlecloud.sql.instance_postgresql_log_disconnections

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := log_disconnections_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_postgresql_log_disconnections({
		"allowed": state == "on",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_log_disconnections_payload({"log_disconnections_state": state}),
	})
}

log_disconnections_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "log_disconnections"

	# the default is "off"
	flag.value == "on"
} else = "off"
