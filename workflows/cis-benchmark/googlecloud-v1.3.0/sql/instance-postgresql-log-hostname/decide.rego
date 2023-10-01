package policy.googlecloud.sql.instance_postgresql_centralized_logging

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := instance_postgresql_centralized_logging_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_postgresql_centralized_logging({
		"allowed": state == "on",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_postgresql_centralized_logging_payload({"pgaudit_enabled": state}),
	})
}

instance_postgresql_centralized_logging_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "cloudsql.enable_pgaudit"

	# the default is "off"
	flag.value == "on"
} else = "off"
