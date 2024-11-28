package policy.aws.waf.classic_rule_condition

import data.shisho
import future.keywords

test_whether_conditions_of_waf_classic_web_rules_are_allowed if {
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
					"__typename": "AWSWAFClassicRule",
					"id": "076d7580-7c9e-4075-b158-0922a92f5111",
					"name": "test-regional-rule-1",
					"predicates": [{
						"dataId": "IPSet",
						"negated": false,
						"type": "IPMatch",
					}],
				}},
				{"details": {}},
				{"details": {
					"__typename": "AWSWAFClassicRateBasedRule",
					"id": "020436c6-6864-4f6a-bfb6-48f23be6b222",
					"name": "test-rate-based-rule-2",
					"predicates": [{
						"dataId": "IPSet",
						"negated": false,
						"type": "IPMatch",
					}],
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
				{"details": {}},
				{"details": {
					"__typename": "AWSWAFClassicRateBasedRule",
					"id": "020436c6-6864-4f6a-bfb6-48f23be6b444",
					"name": "test-rate-based-rule-4",
					"predicates": [{
						"dataId": "IPSet",
						"negated": false,
						"type": "IPMatch",
					}],
				}},
			],
			"tags": [{
				"key": "test-key-2",
				"value": "test-value-2",
			}],
		},
	]}}]}}
}

test_whether_conditions_of_waf_classic_web_rules_are_denied if {
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
					"__typename": "AWSWAFClassicRule",
					"id": "076d7580-7c9e-4075-b158-0922a92f5111",
					"name": "test-regional-rule-1",
					"predicates": [],
				}},
				{"details": {}},
				{"details": {
					"__typename": "AWSWAFClassicRateBasedRule",
					"id": "020436c6-6864-4f6a-bfb6-48f23be6b222",
					"name": "test-rate-based-rule-2",
					"predicates": [],
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
					"__typename": "AWSWAFClassicRule",
					"id": "076d7580-7c9e-4075-b158-0922a92f5333",
					"name": "test-regional-rule-3",
					"predicates": [],
				}},
				{"details": {}},
				{"details": {
					"__typename": "AWSWAFClassicRateBasedRule",
					"id": "020436c6-6864-4f6a-bfb6-48f23be6b444",
					"name": "test-rate-based-rule-4",
					"predicates": [{
						"dataId": "IPSet",
						"negated": false,
						"type": "IPMatch",
					}],
				}},
			],
			"tags": [{
				"key": "test-key-2",
				"value": "test-value-2",
			}],
		},
	]}}]}}
}
