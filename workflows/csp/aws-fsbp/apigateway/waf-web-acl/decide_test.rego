package policy.aws.apigateway.waf_web_acl

import data.shisho
import future.keywords

test_waf_web_acl_for_api_gateway_stages_is_enabled if {
	# the WAF Web ACL is enabled for all API Gateway stages
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbaaaa",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-1",
				"webAclArn": "arn:aws:wafv2:ap-northeast-1:779397777777:regional/webacl/test-web-acl-1/4d97e853-c83b-4dbe-8045-111111111111",
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbbbbb",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-2",
				"webAclArn": "arn:aws:wafv2:ap-northeast-1:779397777777:regional/webacl/test-web-acl-1/4d97e853-c83b-4dbe-8045-222222222222",
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ncccc",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [],
		},
		{},
		{},
	]}}]}}

	# the WAF Web ACL is enabled for all API Gateway stages
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbaaaa",
				"displayName": "rest-api-test-2",
			},
			"stages": [
				{
					"name": "test-stage-1",
					"webAclArn": "",
				},
				{
					"name": "test-stage-2",
					"webAclArn": "arn:aws:wafv2:ap-northeast-1:779397777777:regional/webacl/test-web-acl-1/4d97e853-c83b-4dbe-8045-222222222222",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbbbbb",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-2",
				"webAclArn": "",
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ncccc",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [],
		},
		{},
		{},
	]}}]}}
}
