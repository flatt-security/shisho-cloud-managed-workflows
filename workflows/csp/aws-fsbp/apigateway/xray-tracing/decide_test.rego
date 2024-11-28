package policy.aws.apigateway.xray_tracing

import data.shisho
import future.keywords

test_xray_tracing_for_api_gateway_stages_is_enabled if {
	# the X-Ray tracing is enabled for all API Gateway stages
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbaaaa",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-1",
				"tracingEnabled": true,
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbbbbb",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-2",
				"tracingEnabled": true,
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

	# the X-Ray tracing is not enabled for all API Gateway stages
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
					"tracingEnabled": false,
				},
				{
					"name": "test-stage-2",
					"tracingEnabled": true,
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
				"tracingEnabled": false,
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
