package policy.googlecloud.networking.default_network

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	network_exists := exist_default(project.network.vpcNetworks)

	d := shisho.decision.googlecloud.networking.default_network({
		"allowed": network_exists == false,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.networking.default_network_payload({"default_network_exists": network_exists}),
	})
}

exist_default(vpcNetworks) {
	count(vpcNetworks) > 0
	vpcNetwork := vpcNetworks[_]

	# the default network name is always "default"
	vpcNetwork.name == "default"
} else = false {
	true
}
