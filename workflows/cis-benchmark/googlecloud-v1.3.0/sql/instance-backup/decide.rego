package policy.googlecloud.sql.instance_backup

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	allowed := backup_enabled(instance)

	d := shisho.decision.googlecloud.sql.instance_backup({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_backup_payload({"auto_backup_enabled": allowed}),
	})
}

backup_enabled(i) {
	s := setting(i)
	s.backupConfiguration.enabled
} else = false {
	true
}

setting(i) := i.s1 {
	i.s1 != null
} else := i.s2 {
	i.s2 != null
} else := i.s3 {
	i.s3 != null
} else := i.s4 {
	i.s4 != null
} else := null {
	true
}
