package policy.aws.waf.web_acl_logging

import data.shisho
import future.keywords

test_whether_logging_for_waf_web_acls_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"waf": {"webAcls": [
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|global|2fbb1c33-4491-4ec2-8081-93a4caaaaaaa",
				"displayName": "test-global-web-acl-1",
			},
			"loggingConfiguration": [{"logDestinationConfigurations": "test-destination-1"}],
		},
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|ap-northeast-1|f53055c9-c5ec-4f91-bbe2-9c65bbbbbbbb",
				"displayName": "test-web-acl-1",
			},
			"loggingConfiguration": [{"logDestinationConfigurations": "test-destination-2"}],
		},
	]}}]}}
}

test_whether_logging_for_waf_web_acls_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"waf": {"webAcls": [
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|global|2fbb1c33-4491-4ec2-8081-93a4caaaaaaa",
				"displayName": "test-global-web-acl-1",
			},
			"loggingConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-waf-classic-web-acl|ap-northeast-1|f53055c9-c5ec-4f91-bbe2-9c65bbbbbbbb",
				"displayName": "test-web-acl-1",
			},
			"loggingConfiguration": null,
		},
	]}}]}}
}
