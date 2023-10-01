package policy.googlecloud.sql.instance_sqlserver_user_options

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	configured := user_options_configured(instance.settings.databaseFlags)

	d := shisho.decision.googlecloud.sql.instance_sqlserver_user_options({
		"allowed": configured == false,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_sqlserver_user_options_payload({"user_options_configured": configured}),
	})
}

user_options_configured(database_flags) {
	flag := database_flags[_]
	flag.name == "user options"
} else = false
