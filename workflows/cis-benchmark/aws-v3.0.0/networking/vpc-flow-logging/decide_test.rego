package policy.aws.networking.vpc_flow_logging

import data.shisho
import future.keywords

test_flow_logging_is_enabled_for_vpcs if {
	# check if flow logging is enabled for VPCs
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b88888",
				"displayName": "vpc-0fb9667dee2b88888",
			},
			"flowLogs": [
				{"id": "fl-061ce974280e965b2"},
				{"id": "fl-05a3f35a72edeb158"},
			],
		},
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-06dc8a2abafd99999",
				"displayName": "vpc-06dc8a2abafd99999",
			},
			"flowLogs": [{"id": "fl-0791e8000f7ea0a3a"}],
		},
	]}}]}}

	# check if flow logging is not enabled for VPCs
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-1|vpc-0fc5a1285f1377777",
				"displayName": "vpc-0fc5a1285f1377777",
			},
			"flowLogs": [],
		},
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-2|vpc-0f31afb4562400000",
				"displayName": "vpc-0f31afb4562400000",
			},
			"flowLogs": [],
		},
	]}}]}}
}
