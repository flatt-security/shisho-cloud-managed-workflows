package policy.googlecloud.sql.instance_mysql_local_infile

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	state := local_infile_state(instance.settings.databaseFlags)
	d := shisho.decision.googlecloud.sql.instance_mysql_local_infile({
		"allowed": state == "off",
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_mysql_local_infile_payload({"local_infile_state": state}),
	})
}

local_infile_state(database_flags) := flag.value {
	flag := database_flags[_]
	flag.name == "local_infile"

	# the default is "on"
	flag.value == "off"
} else = "on"
