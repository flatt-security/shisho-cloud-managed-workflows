package policy.googlecloud.sql.instance_sqlserver_external_scripts

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := external_scripts_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_sqlserver_external_scripts({
		"allowed": state == "off",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_external_scripts_payload({"external_scripts_state": state}),
	})
}

# the default value is "off"
external_scripts_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "external scripts enabled"
} else = "off"
