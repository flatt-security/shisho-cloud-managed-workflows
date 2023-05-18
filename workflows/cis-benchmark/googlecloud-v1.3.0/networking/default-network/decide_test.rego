package policy.googlecloud.networking.default_network

import data.shisho
import future.keywords

test_whether_default_network_does_not_exist if {
	# check if the default network does not exist on VPC Network list
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"metadata": {"id": "googlecloud-project|354711641168"},
			"network": {"vpcNetworks": [
				{"name": "test-network-1"},
				{"name": "test-network-2"},
			]},
		},
		{
			"id": "test-project-2",
			"metadata": {"id": "googlecloud-project|354711641169"},
			"network": {"vpcNetworks": [
				{"name": "test-network-1"},
				{"name": "test-network-2"},
				{"name": "test-network-3"},
			]},
		},
		{
			"id": "test-project-2",
			"metadata": {"id": "googlecloud-project|354711641160"},
			"network": {"vpcNetworks": []},
		},
	]}}

	# check if the default networks exist on VPC Network list
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"metadata": {"id": "googlecloud-project|354711641168"},
			"network": {"vpcNetworks": [
				{"name": "default"},
				{"name": "test-network-2"},
			]},
		},
		{
			"id": "test-project-2",
			"metadata": {"id": "googlecloud-project|354711641169"},
			"network": {"vpcNetworks": [
				{"name": "default"},
				{"name": "test-network-2"},
				{"name": "test-network-3"},
			]},
		},
	]}}
}
