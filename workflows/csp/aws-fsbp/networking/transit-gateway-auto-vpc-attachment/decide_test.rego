package policy.aws.networking.transit_gateway_auto_vpc_attachment

import data.shisho
import future.keywords

test_whether_auto_vpc_attachment_for_transit_gateways_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"transitGateways": [
		{
			"metadata": {
				"id": "aws-network-transit-gateway|ap-northeast-1|tgw-0e8dd651f061a47b2",
				"displayName": "tgw-0e8dd651f061a47b2",
			},
			"options": {"autoAcceptSharedAttachments": "DISABLE"},
		},
		{
			"metadata": {
				"id": "aws-network-transit-gateway|ap-northeast-1|tgw-0e8dd651f061a47c1",
				"displayName": "tgw-0e8dd651f061a47c1",
			},
			"options": {"autoAcceptSharedAttachments": "DISABLE"},
		},
	]}}]}}
}

test_whether_auto_vpc_attachment_for_transit_gateways_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"transitGateways": [
		{
			"metadata": {
				"id": "aws-network-transit-gateway|ap-northeast-1|tgw-0e8dd651f061a47b2",
				"displayName": "tgw-0e8dd651f061a47b2",
			},
			"options": {"autoAcceptSharedAttachments": "ENABLE"},
		},
		{
			"metadata": {
				"id": "aws-network-transit-gateway|ap-northeast-1|tgw-0e8dd651f061a47c1",
				"displayName": "tgw-0e8dd651f061a47c1",
			},
			"options": {"autoAcceptSharedAttachments": "ENABLE"},
		},
	]}}]}}
}
