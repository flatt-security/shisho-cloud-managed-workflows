package policy.googlecloud.sql.instance_sqlserver_remote_access

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := remote_access_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_sqlserver_remote_access({
		"allowed": state == "off",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_remote_access_payload({"remote_access_state": state}),
	})
}

# the default is "on"
remote_access_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "remote access"
} else = "on"
