package policy.googlecloud.dns.dnssec_ksk_algorithm

import data.shisho
import future.keywords

test_whether_dnssec_is_enabled_for_dns_managed_zones if {
	# check if the DNSSEC is enabled for DNS managed zones
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417662"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "ECDSAP256SHA256",
						"type": "ZONE_SIGNING",
					}]},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "RSASHA256",
						"type": "ZONE_SIGNING",
					}]},
				},
				{
					"metadata": {"id": "googlecloud-nw-dns-managed-zone|924052224636|3308548985978267777"},
					"dnssecConfiguration": {"defaultKeySpecs": []},
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481418888"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "RSASHA512",
						"type": "ZONE_SIGNING",
					}]},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481419999"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "ECDSAP384SHA384",
						"type": "ZONE_SIGNING",
					}]},
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
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "RSASHA1",
						"type": "ZONE_SIGNING",
					}]},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641168|9006941500481417777"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "RSASHA1",
						"type": "ZONE_SIGNING",
					}]},
				},
			]},
		},
		{
			"id": "test-project-2",
			"network": {"dnsManagedZones": [
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481418888"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "RSASHA1",
						"type": "ZONE_SIGNING",
					}]},
				},
				{
					"metadata": {"id": "googlecloud-nw-vpc-network|354711641222|9006941500481419999"},
					"dnssecConfiguration": {"defaultKeySpecs": [{
						"algorithm": "RSASHA1",
						"type": "ZONE_SIGNING",
					}]},
				},
			]},
		},
	]}}
}
