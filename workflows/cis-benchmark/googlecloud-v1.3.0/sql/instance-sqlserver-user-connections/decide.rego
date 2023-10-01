package policy.googlecloud.sql.instance_sqlserver_user_connections

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	amount := user_connections_state(instance.settings.databaseFlags)

	# the maximum is 32,767 user connections
	# the default is 0 and it means that the maximum (32,767) user connections are allowed
	allowed := amount == 0

	d := shisho.decision.googlecloud.sql.instance_sqlserver_user_connections({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_user_connections_payload({"maximum_user_connections": amount}),
	})
}

# the default value is "off"
user_connections_state(database_flags) := x {
	flag := database_flags[_]
	flag.name == "user connections"
	x := to_number(flag.value)
} else = 0
