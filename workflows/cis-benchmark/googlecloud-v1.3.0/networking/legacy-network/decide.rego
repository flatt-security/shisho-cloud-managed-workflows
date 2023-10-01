package policy.googlecloud.networking.legacy_network

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	vpcNetwork := project.network.vpcNetworks[_]

	d := shisho.decision.googlecloud.networking.legacy_network({
		"allowed": vpcNetwork.subnetworkMode != "LEGACY",
		"subject": vpcNetwork.metadata.id,
		"payload": shisho.decision.googlecloud.networking.legacy_network_payload({
			"name": vpcNetwork.metadata.displayName,
			"subnetwork_mode": vpcNetwork.subnetworkMode,
		}),
	})
}
