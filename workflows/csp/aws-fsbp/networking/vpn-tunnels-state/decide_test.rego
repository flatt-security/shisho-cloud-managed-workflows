package policy.aws.networking.vpn_tunnels_state

import data.shisho
import future.keywords

test_whether_vpn_tunnels_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpnConnections": [
		{
			"metadata": {
				"id": "aws-network-vpn-connection|ap-northeast-1|vpn-029940c35cc5a129a",
				"displayName": "vpn-029940c35cc5a129a",
			},
			"vgwTelemetry": [
				{
					"outsideIpAddress": "35.74.181.197",
					"status": "UP",
				},
				{
					"outsideIpAddress": "54.65.223.28",
					"status": "UP",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-network-vpn-connection|ap-northeast-1|vpn-029940c35cc5a128b",
				"displayName": "vpn-029940c35cc5a128b",
			},
			"vgwTelemetry": [
				{
					"outsideIpAddress": "35.74.181.196",
					"status": "UP",
				},
				{
					"outsideIpAddress": "54.65.223.27",
					"status": "UP",
				},
			],
		},
	]}}]}}
}

test_whether_vpn_tunnels_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpnConnections": [
		{
			"metadata": {
				"id": "aws-network-vpn-connection|ap-northeast-1|vpn-029940c35cc5a128b",
				"displayName": "vpn-029940c35cc5a128b",
			},
			"vgwTelemetry": [
				{
					"outsideIpAddress": "35.74.181.196",
					"status": "UP",
				},
				{
					"outsideIpAddress": "54.65.223.27",
					"status": "DOWN",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-network-vpn-connection|ap-northeast-1|vpn-029940c35cc5a127c",
				"displayName": "vpn-029940c35cc5a127c",
			},
			"vgwTelemetry": [
				{
					"outsideIpAddress": "35.74.181.195",
					"status": "DOWN",
				},
				{
					"outsideIpAddress": "54.65.223.26",
					"status": "DOWN",
				},
			],
		},
	]}}]}}
}
