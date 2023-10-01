package policy.googlecloud.networking.ssh_access

import data.shisho
import future.keywords

test_whether_ssh_is_disabled_by_firewall_policies if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 6 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"vpcNetworks": [
				{
					# allowed (the ingress is allowed, but tcp & sctp/22 itself is not allowed)
					"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120417777"},
					"firewallRules": [
						{
							"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-1",
							"allowed": [{
								"ipProtocol": "tcp",
								"ports": [{"from": 80, "to": 80}],
							}],
							"direction": "INGRESS",
							"sourceRanges": ["0.0.0.0/0"],
						},
						{
							"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-2",
							"allowed": [{
								"ipProtocol": "udp",
								"ports": [{"from": 22, "to": 22}],
							}],
							"direction": "INGRESS",
							"sourceRanges": ["0.0.0.0/0"],
						},
					],
				},
				{
					# allowed (no allow ingress rule)
					"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120416666"},
					"firewallRules": [{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-1",
						"allowed": [],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					}],
				},
				{
					# allowed (ip-level source range isn't defined)
					"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120415555"},
					"firewallRules": [
						{
							"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-1",
							"allowed": [{
								"ipProtocol": "tcp",
								"ports": [{"from": 80, "to": 80}],
							}],
							"direction": "INGRESS",
							"sourceRanges": [],
						},
						{
							"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-2",
							"allowed": [{
								"ipProtocol": "udp",
								"ports": [{"from": 22, "to": 22}],
							}],
							"direction": "INGRESS",
							"sourceRanges": [],
						},
					],
				},
				{
					# allowed (the ingress is restricted by implicit rules)
					"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120414444"},
					"firewallRules": [{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-1",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [],
						}],
						"direction": "EGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					}],
				},
				{
					# allowed (implicit rules block the ingress)
					"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120413333"},
					"firewallRules": [],
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"vpcNetworks": [{
				# allowed (the source is limited)
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120418888"},
				"firewallRules": [
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/networks/test-1",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [{"from": 22, "to": 22}],
						}],
						"direction": "EGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/networks/test-2",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [{"from": 22, "to": 22}],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["35.235.240.0/20"],
					},
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/networks/test-3",
						"allowed": [{
							"ipProtocol": "sctp",
							"ports": [{"from": 22, "to": 22}],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["35.235.240.0/20"],
					},
				],
			}]},
		},
	]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120418888"},
				"firewallRules": [
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-1",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [{"from": 22, "to": 22}],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-2",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [{"from": 0, "to": 22}],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
				],
			}]},
		},
		{
			"id": "test-project-2",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120419999"},
				"firewallRules": [
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/networks/test-1",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/networks/test-2",
						"allowed": [{
							"ipProtocol": "tcp",
							"ports": [],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
				],
			}]},
		},
		{
			"id": "test-project-3",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120433333"},
				"firewallRules": [
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-3/global/networks/test-1",
						"allowed": [{
							"ipProtocol": "sctp",
							"ports": [{"from": 22, "to": 22}],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
					{
						"network": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/networks/test-2",
						"allowed": [{
							"ipProtocol": "sctp",
							"ports": [{"from": 0, "to": 22}],
						}],
						"direction": "INGRESS",
						"sourceRanges": ["0.0.0.0/0"],
					},
				],
			}]},
		},
		{
			"id": "test-project-4",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56580586120444444"},
				"firewallRules": [{
					"network": "https://www.googleapis.com/compute/v1/projects/test-project-4/global/networks/test-1",
					"allowed": [{
						"ipProtocol": "sctp",
						"ports": [],
					}],
					"direction": "INGRESS",
					"sourceRanges": ["0.0.0.0/0"],
				}],
			}]},
		},
	]}}
}
