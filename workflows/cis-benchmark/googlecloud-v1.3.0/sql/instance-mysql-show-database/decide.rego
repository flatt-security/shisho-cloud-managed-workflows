package policy.googlecloud.sql.instance_mysql_show_database

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := skip_show_database_state(instance.settings.databaseFlags)
	d := shisho.decision.googlecloud.sql.instance_mysql_show_database({
		"allowed": state == "on",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_mysql_show_database_payload({"skip_show_database_state": state}),
	})
}

skip_show_database_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "skip_show_database"

	# the default is "off"
	flag.value == "on"
} else = "off"
