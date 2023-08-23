package policy.aws.networking.acl_ingress

import data.shisho
import future.keywords

test_policy_detects_insecure_nacls if {
	acls := [{
		"id": "acl-030f74e1b061fda66",
		"entries": [
			{
				"cidrBlock": "0.0.0.0/0",
				"ipv6CidrBlock": "",
				"ruleAction": "ALLOW",
				"type": "EGRESS",
				"portRange": {
					"from": 0,
					"to": 0,
				},
			},
			{
				"cidrBlock": "0.0.0.0/0",
				"ipv6CidrBlock": "",
				"ruleAction": "DENY",
				"type": "EGRESS",
				"portRange": {
					"from": 0,
					"to": 0,
				},
			},
			{
				"cidrBlock": "0.0.0.0/0",
				"ipv6CidrBlock": "",
				"ruleAction": "ALLOW",
				"type": "INGRESS",
				"portRange": {
					"from": 0,
					"to": 0,
				},
			},
			{
				"cidrBlock": "0.0.0.0/0",
				"ipv6CidrBlock": "",
				"ruleAction": "DENY",
				"type": "INGRESS",
				"portRange": {
					"from": 0,
					"to": 0,
				},
			},
		],
	}]

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"network": {"vpcs": [{
		"metadata": {"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00"},
		"acls": acls,
	}]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"network": {"vpcs": [{
		"metadata": {"id": "aws-vpc|ap-northeast-1|vpc-0fb9667dee2b36e00"},
		"acls": acls,
		"tags": [{"key": "foo", "value": "bar=piyo"}],
	}]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
