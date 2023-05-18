package policy.googlecloud.networking.vpc_flow_log

import data.shisho
import future.keywords

test_whether_flow_logging_is_configured_properly_for_subnetworks if {
	# check if the flow logging is configured properly for subnetworks
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56522586120417777"},
				"subnetworks": [
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": true,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": true,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
				],
			}]},
		},
		{
			"id": "test-project-2",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56522586120418888"},
				"subnetworks": [
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": true,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": true,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
				],
			}]},
		},
		{
			"id": "test-project-3",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56522586120419999"},
				"subnetworks": [],
			}]},
		},
	]}}

	# check if the flow logging is not configured properly for subnetworks
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56522586120411111"},
				"subnetworks": [
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": false,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_10_MIN",
						"enable": true,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
				],
			}]},
		},
		{
			"id": "test-project-2",
			"network": {"vpcNetworks": [{
				"metadata": {"id": "googlecloud-nw-vpc-network|514893255555|56522586120412222"},
				"subnetworks": [
					{"logConfiguration": {
						"filterExpression": "",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": true,
						"flowSampling": 0.5,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
					{"logConfiguration": {
						"filterExpression": "b[aeiou]bble",
						"aggregationInterval": "INTERVAL_5_SEC",
						"enable": true,
						"flowSampling": 1,
						"metadata": "INCLUDE_ALL_METADATA",
					}},
				],
			}]},
		},
	]}}
}
