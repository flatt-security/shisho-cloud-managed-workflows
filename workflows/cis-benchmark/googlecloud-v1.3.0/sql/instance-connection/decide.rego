package policy.googlecloud.sql.instance_connection

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	requires_tls := instance.settings.ipConfiguration.requireSsl
	d := shisho.decision.googlecloud.sql.instance_connection({
		"allowed": requires_tls,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_connection_payload({"tls_required": requires_tls}),
	})
}
