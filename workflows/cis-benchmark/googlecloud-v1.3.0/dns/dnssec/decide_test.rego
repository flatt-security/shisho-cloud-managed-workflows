package policy.googlecloud.dns.dnssec

import data.shisho
import future.keywords

test_whether_dnssec_is_enabled_for_dns_managed_zones if {
	# check if the DNSSEC is enabled for DNS managed zones
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"dnssecConfiguration": {"state": "ON"},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"dnssecConfiguration": {"state": "ON"},
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481418888"},
					"dnssecConfiguration": {"state": "ON"},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481419999"},
					"dnssecConfiguration": {"state": "ON"},
				},
			]},
		},
	]}}

	# check if the DNSSEC is disabled for DNS managed zones
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"dnssecConfiguration": {"state": "OFF"},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"dnssecConfiguration": {"state": "TRANSFER"},
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481418888"},
					"dnssecConfiguration": {"state": "OFF"},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481419999"},
					"dnssecConfiguration": {"state": "OFF"},
				},
			]},
		},
	]}}
}
