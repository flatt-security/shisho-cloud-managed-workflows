package policy.aws.networking.fp_stateless_action

import data.shisho
import future.keywords

test_whether_stateless_actions_of_firewall_policies_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{"firewalls": [{
			"metadata": {
				"id": "aws-network-firewall|ap-northeast-1|801aafb1-86a3-45a9-a9b1-2c79465aaaaa",
				"displayName": "test-firewall-1",
			},
			"firewallPolicy": {"statelessDefaultActions": ["aws:drop"]},
		}]},
		{"firewalls": [{
			"metadata": {
				"id": "aws-network-firewall|ap-northeast-1|801aafb1-86a3-45a9-a9b1-2c79465bbbbb",
				"displayName": "test-firewall-2",
			},
			"firewallPolicy": {"statelessDefaultActions": ["aws:forward_to_sfe"]},
		}]},
		{"firewalls": [{
			"metadata": {
				"id": "aws-network-firewall|ap-northeast-1|801aafb1-86a3-45a9-a9b1-2c79465ccccc",
				"displayName": "test-firewall-3",
			},
			"firewallPolicy": {"statelessDefaultActions": [
				"aws:drop",
				"aws:forward_to_sfe",
			]},
		}]},
		{"firewalls": []},
	]}}]}}
}

test_whether_stateless_actions_of_firewall_policies_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{"firewalls": [{
			"metadata": {
				"id": "aws-network-firewall|ap-northeast-1|801aafb1-86a3-45a9-a9b1-2c79465ccccc",
				"displayName": "test-firewall-3",
			},
			"firewallPolicy": {"statelessDefaultActions": ["aws:pass"]},
		}]},
		{"firewalls": [{
			"metadata": {
				"id": "aws-network-firewall|ap-northeast-1|801aafb1-86a3-45a9-a9b1-2c79465ddddd",
				"displayName": "test-firewall-4",
			},
			"firewallPolicy": {"statelessDefaultActions": []},
		}]},
		{"firewalls": []},
	]}}]}}
}
