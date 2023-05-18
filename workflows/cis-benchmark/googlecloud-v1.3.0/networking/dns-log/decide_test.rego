package policy.googlecloud.networking.dns_log

import data.shisho
import future.keywords

test_whether_logging_is_enabled_for_DNS if {
	# check if the logging is enabled for DNS
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"dnsPolicies": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"enableLogging": true,
					"networks": [],
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"enableLogging": true,
					"networks": [],
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"dnsPolicies": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481418888"},
					"enableLogging": true,
					"networks": [],
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481419999"},
					"enableLogging": true,
					"networks": [],
				},
			]},
		},
	]}}

	# check if the logging is disabled for DNS
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"dnsPolicies": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"enableLogging": true,
					"networks": [],
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"enableLogging": false,
					"networks": [],
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"dnsPolicies": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481418888"},
					"enableLogging": true,
					"networks": [],
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481419999"},
					"enableLogging": false,
					"networks": [],
				},
			]},
		},
	]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [{
		"id": "test-project-1",
		"network": {
			"vpcNetworks": [
				{
					# Has no DNS policy; hence this should be denied
					"metadata": {"id": "googlecloud-nw-vpc-network|514893259785|3345992333810760640"},
					"selfLink": "https://www.googleapis.com/compute/v1/projects/shisho-security-dev-tools/global/networks/default",
				},
				{
					# Has a DNS policy with logging disabled; hence this should be denied
					"metadata": {"id": "googlecloud-nw-vpc-network|514893259785|8757077963369764575"},
					"selfLink": "https://www.googleapis.com/compute/v1/projects/shisho-security-dev-tools/global/networks/fef4g4-network",
				},
				{
					# Has a DNS policy with logging enabled; hence this should be allowed
					"metadata": {"id": "googlecloud-nw-vpc-network|514893259785|4324324324324324324"},
					"selfLink": "https://www.googleapis.com/compute/v1/projects/shisho-security-dev-tools/global/networks/g4g43g2g2-network",
				},
			],
			"dnsPolicies": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"enableLogging": true,
					"networks": [],
				},
				{
					# In addition to the network, this should be also reported as denied.
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"enableLogging": false,
					"networks": [],
				},
				{
					# In addition to the network, this should be also reported as denied.
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"enableLogging": false,
					"networks": [{"url": "https://www.googleapis.com/compute/v1/projects/shisho-security-dev-tools/global/networks/syamakawa-network"}],
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481437777"},
					"enableLogging": true,
					"networks": [{"url": "https://www.googleapis.com/compute/v1/projects/shisho-security-dev-tools/global/networks/g4g43g2g2-network"}],
				},
			],
		},
	}]}}
}
