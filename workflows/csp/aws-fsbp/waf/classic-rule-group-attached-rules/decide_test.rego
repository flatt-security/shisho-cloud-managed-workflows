package policy.aws.waf.classic_rule_group_attached_rules

import data.shisho
import future.keywords

test_whether_rules_of_waf_classic_web_rule_groups_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"wafClassic": {"webAcls": [
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|ap-northeast-1|f53055c9-c5ec-4f91-bbe2-9c65bd6f9111",
				"displayName": "test-web-acl-1",
			},
			"activatedRules": [
				{"details": {
					"id": "abc20cc0-3afa-4856-b0e3-de3b2f841aaa",
					"name": "etst-regional-rule-group-1",
					"rules": [{"details": {"id": "076d7580-7c9e-4075-b158-0922a92f5111"}}],
				}},
				{"details": {
					"id": "abc20cc0-3afa-4856-b0e3-de3b2f841bbb",
					"name": "etst-regional-rule-group-2",
					"rules": [{"details": {"id": "076d7580-7c9e-4075-b158-0922a92f5222"}}],
				}},
			],
			"tags": [{
				"key": "test-key-2",
				"value": "test-value-2",
			}],
		},
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|ap-northeast-1|f53055c9-c5ec-4f91-bbe2-9c65bd6f9222",
				"displayName": "test-web-acl-2",
			},
			"activatedRules": [{"details": {
				"id": "abc20cc0-3afa-4856-b0e3-de3b2f841ccc",
				"name": "etst-regional-rule-group-3",
				"rules": [{"details": {"id": "076d7580-7c9e-4075-b158-0922a92f5333"}}],
			}}],
			"tags": [{
				"key": "test-key-2",
				"value": "test-value-2",
			}],
		},
	]}}]}}
}

test_whether_rules_of_waf_classic_web_rule_groups_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"wafClassic": {"webAcls": [
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|ap-northeast-1|f53055c9-c5ec-4f91-bbe2-9c65bd6f9111",
				"displayName": "test-web-acl-1",
			},
			"activatedRules": [
				{"details": {
					"id": "abc20cc0-3afa-4856-b0e3-de3b2f841aaa",
					"name": "etst-regional-rule-group-1",
					"rules": [],
				}},
				{"details": {
					"id": "abc20cc0-3afa-4856-b0e3-de3b2f841bbb",
					"name": "etst-regional-rule-group-2",
					"rules": [],
				}},
			],
			"tags": [{
				"key": "test-key-2",
				"value": "test-value-2",
			}],
		},
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|ap-northeast-1|f53055c9-c5ec-4f91-bbe2-9c65bd6f9222",
				"displayName": "test-web-acl-2",
			},
			"activatedRules": [
				{"details": {
					"id": "abc20cc0-3afa-4856-b0e3-de3b2f841ccc",
					"name": "etst-regional-rule-group-3",
					"rules": [],
				}},
				{"details": {
					"id": "abc20cc0-3afa-4856-b0e3-de3b2f841ddd",
					"name": "etst-regional-rule-group-4",
					"rules": [],
				}},
			],
			"tags": [{
				"key": "test-key-2",
				"value": "test-value-2",
			}],
		},
	]}}]}}
}
