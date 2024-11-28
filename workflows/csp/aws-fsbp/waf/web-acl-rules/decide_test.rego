package policy.aws.waf.web_acl_rules

import data.shisho
import future.keywords

test_whether_rules_for_waf_web_acls_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"waf": {"webAcls": [
		{
			"metadata": {
				"id": "aws-waf-web-acl|global|61449942-167d-4a33-ba1c-17ac016837a5",
				"displayName": "test-global-web-acl-1",
			},
			"rules": [
				{"name": "AWS-AWSManagedRulesAmazonIpReputationList"},
				{"name": "AWS-AWSManagedRulesCommonRuleSet"},
				{"name": "AWS-AWSManagedRulesKnownBadInputsRuleSet"},
			],
		},
		{
			"metadata": {
				"id": "aws-waf-web-acl|ap-northeast-1|ec029297-1238-4dd3-a428-dcc90867d393",
				"displayName": "test-web-acl-1",
			},
			"rules": [{"name": "AWS-AWSManagedRulesAmazonIpReputationList"}],
		},
	]}}]}}
}

test_whether_rules_for_waf_web_acls_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"waf": {"webAcls": [
		{
			"metadata": {
				"id": "aws-waf-web-acl|global|61449942-167d-4a33-ba1c-17ac016837a5",
				"displayName": "test-global-web-acl-1",
			},
			"rules": [],
		},
		{
			"metadata": {
				"id": "aws-waf-web-acl|ap-northeast-1|ec029297-1238-4dd3-a428-dcc90867d393",
				"displayName": "test-web-acl-1",
			},
			"rules": [],
		},
	]}}]}}
}
