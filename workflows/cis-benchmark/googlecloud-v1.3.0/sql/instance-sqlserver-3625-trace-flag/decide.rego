package policy.googlecloud.sql.instance_sqlserver_3625_trace_flag

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := trace_flag_state(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_sqlserver_3625_trace_flag({
		"allowed": state == "off",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_3625_trace_flag_payload({"trace_flag_state": state}),
	})
}

# the default is "off"
trace_flag_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "3625"
} else = "off"
