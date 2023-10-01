package policy.googlecloud.sql.instance_sqlserver_cross_db_ownership_chaining

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := instance_sqlserver_cross_db_ownership_chaining_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_sqlserver_cross_db_ownership_chaining({
		"allowed": state == "off",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_cross_db_ownership_chaining_payload({"cross_db_ownership_chaining_state": state}),
	})
}

# the default value is "off"
instance_sqlserver_cross_db_ownership_chaining_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "cross db ownership chaining"
} else = "off"
