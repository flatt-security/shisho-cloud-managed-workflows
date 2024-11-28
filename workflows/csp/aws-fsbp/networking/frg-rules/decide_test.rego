package policy.aws.networking.frg_rules

import data.shisho
import future.keywords

test_whether_rules_of_firewall_rule_groups_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"firewallRuleGroups": [
		{
			"metadata": {
				"id": "aws-network-firewall-rule-group|ap-northeast-1|stateless|580c8e33-62d2-4a3c-b7fe-a3238fcaaaaa",
				"displayName": "test-stateless-rule-group-1",
			},
			"rules": {"source": {"rulesAndCustomActions": {"rules": [{"priority": 1}]}}},
		},
		{
			"metadata": {
				"id": "aws-network-firewall-rule-group|ap-northeast-1|stateless|580c8e33-62d2-4a3c-b7fe-a3238fcbbbbb",
				"displayName": "test-stateless-rule-group-2",
			},
			"rules": {"source": {"rulesAndCustomActions": {"rules": [{"priority": 1}]}}},
		},
	]}}]}}
}

test_whether_rules_of_firewall_rule_groups_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"network": {"firewallRuleGroups": [
		{
			"metadata": {
				"id": "aws-network-firewall-rule-group|ap-northeast-1|stateless|580c8e33-62d2-4a3c-b7fe-a3238fcaaaaa",
				"displayName": "test-stateless-rule-group-1",
			},
			"rules": {"source": {"rulesAndCustomActions": {"rules": []}}},
		},
		{
			"metadata": {
				"id": "aws-network-firewall-rule-group|ap-northeast-1|stateless|580c8e33-62d2-4a3c-b7fe-a3238fcbbbbb",
				"displayName": "test-stateless-rule-group-2",
			},
			"rules": {"source": {"rulesAndCustomActions": {"rules": []}}},
		},
		{
			"metadata": {
				"id": "aws-network-firewall-rule-group|ap-northeast-1|stateless|580c8e33-62d2-4a3c-b7fe-a3238fcccccc",
				"displayName": "test-stateless-rule-group-3",
			},
			"rules": {"source": null},
		},
	]}}]}}
}
