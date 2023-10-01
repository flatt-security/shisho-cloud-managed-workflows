package policy.googlecloud.sql.instance_sqlserver_contained_db_authentication

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := contained_db_authentication_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_sqlserver_contained_db_authentication({
		"allowed": state == "off",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_contained_db_authentication_payload({"contained_db_authentication_state": state}),
	})
}

# the default is "off"
contained_db_authentication_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "contained database authentication"
} else = "off"
