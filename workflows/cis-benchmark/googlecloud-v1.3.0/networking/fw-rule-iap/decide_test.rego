package policy.googlecloud.networking.fw_rule_iap

import data.shisho
import future.keywords

test_whether_firewall_rules_for_iap_are_allowed if {
	# Within the Google ranges #1
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777771"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [{
				"ipProtocol": "tcp",
				"ports": [{
					"from": 80,
					"to": 80,
				}],
			}],
			"direction": "INGRESS",
			"sourceRanges": ["35.235.240.0/20"],
		}],
	}

	# Within the Google ranges #2
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777772"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [{
				"ipProtocol": "tcp",
				"ports": [{
					"from": 80,
					"to": 80,
				}],
			}],
			"direction": "INGRESS",
			"sourceRanges": ["35.235.240.1/32"],
		}],
	}

	# Out of the Google ranges, but it has no allow rules (-> implied rules will block traffic so it's okay)
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777773"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [],
			"direction": "INGRESS",
			"sourceRanges": ["0.0.0.0/0"],
		}],
	}

	# Out of the Google ranges, but it's on unrestricted ports
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777774"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [{
				"ipProtocol": "tcp",
				"ports": [{
					"from": 1024,
					"to": 65535,
				}],
			}],
			"direction": "INGRESS",
			"sourceRanges": ["0.0.0.0/0"],
		}],
	}

	# Out of the Google ranges, but it's an EGRESS rule
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777775"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [{
				"ipProtocol": "tcp",
				"ports": [{
					"from": 80,
					"to": 80,
				}],
			}],
			"direction": "EGRESS",
			"sourceRanges": ["0.0.0.0/0"],
		}],
	}

	# Out of the Google ranges, but it's on unrestricted protocols
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777776"},
		"firewallRules": [{
			"name": "test-firewall-rule-6",
			"allowed": [{
				"ipProtocol": "udp",
				"ports": [{
					"from": 80,
					"to": 80,
				}],
			}],
			"direction": "INGRESS",
			"sourceRanges": ["0.0.0.0/0"],
		}],
	}
}

test_whether_firewall_rules_for_iap_are_denied if {
	# Out of the Google ranges
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777771"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [{
				"ipProtocol": "tcp",
				"ports": [{
					"from": 80,
					"to": 80,
				}],
			}],
			"direction": "INGRESS",
			"sourceRanges": ["0.0.0.0/0"],
		}],
	}

	# Out of the Google ranges (without a specific port range)
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777772"},
		"firewallRules": [{
			"name": "test-firewall-rule-1",
			"allowed": [{
				"ipProtocol": "tcp",
				"ports": [],
			}],
			"direction": "INGRESS",
			"sourceRanges": ["0.0.0.0/0"],
		}],
	}

	# Out of the Google ranges (multiple rules, only one violation)
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"metadata": {"id": "googlecloud-nw-vpc-network|514897777777|3345992333817777771"},
		"firewallRules": [
			{
				"name": "test-firewall-rule-1",
				"allowed": [{
					"ipProtocol": "tcp",
					"ports": [{
						"from": 80,
						"to": 80,
					}],
				}],
				"direction": "INGRESS",
				"sourceRanges": ["35.235.240.0/20"],
			},
			{
				"name": "test-firewall-rule-1",
				"allowed": [{
					"ipProtocol": "tcp",
					"ports": [{
						"from": 80,
						"to": 80,
					}],
				}],
				"direction": "INGRESS",
				"sourceRanges": ["0.0.0.0/0"],
			},
		],
	}
}
