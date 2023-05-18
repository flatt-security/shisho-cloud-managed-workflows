package policy.googlecloud.sql.instance_accessibility

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	public := allows_public_traffic(instance.settings.ipConfiguration.authorizedNetworks)
	d := shisho.decision.googlecloud.sql.instance_accessibility({
		"allowed": public == false,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_accessibility_payload({"ip_allowlist": [network.name |
			network := instance.settings.ipConfiguration.authorizedNetworks[_]
			network.value == "0.0.0.0/0"
		]}),
	})
}

allows_public_traffic(authorized_networks) {
	network := authorized_networks[_]
	network.value == "0.0.0.0/0"
} else = false
