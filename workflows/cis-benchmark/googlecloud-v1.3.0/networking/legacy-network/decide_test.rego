package policy.googlecloud.networking.legacy_network

import data.shisho
import future.keywords

test_whether_networks_are_not_legacy_networks if {
	# check if the networks are not legacy networks
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"network": {"vpcNetworks": [
		{
			"metadata": {
				"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777777",
				"displayName": "test-network-1",
			},
			"subnetworkMode": "AUTO",
		},
		{
			"metadata": {
				"id": "googlecloud-nw-vpc-network|514898888888|8757077963368888888",
				"displayName": "test-network-2",
			},
			"subnetworkMode": "CUSTOM",
		},
	]}}]}}

	# check if the default networks exist on VPC Network list
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"network": {"vpcNetworks": [
		{
			"metadata": {
				"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777777",
				"displayName": "test-network-1",
			},
			"subnetworkMode": "LEGACY",
		},
		{
			"metadata": {
				"id": "googlecloud-nw-vpc-network|514898888888|8757077963368888888",
				"displayName": "test-network-2",
			},
			"subnetworkMode": "LEGACY",
		},
	]}}]}}
}
