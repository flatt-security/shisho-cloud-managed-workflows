package policy.aws.apigateway.logging

import data.shisho
import future.keywords

test_logging_for_api_gateway_stages_is_enabled if {
	# the logging level is set to INFO or ERROR for all API Gateway stages
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"__typename": "AWSAPIGatewayRestAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aaa",
				"displayName": "rest-api-test-1",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {"loggingLevel": "INFO"},
				}],
			}],
		},
		{
			"__typename": "AWSAPIGatewayRestAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aab",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {"loggingLevel": "ERROR"},
				}],
			}],
		},
		{
			"__typename": "AWSAPIGatewayRestAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ntbbb",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [],
		},
		{
			"__typename": "AWSAPIGatewayWebSocketAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|websocket|2sebg6qccc",
				"displayName": "websocket-api-test-5",
			},
			"stages": [{
				"name": "teststage",
				"defaultRouteSettings": {"loggingLevel": "INFO"},
			}],
		},
		{
			"__typename": "AWSAPIGatewayWebSocketAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|websocket|2sebg6qddd",
				"displayName": "websocket-api-test-7",
			},
			"stages": [{
				"name": "teststage",
				"defaultRouteSettings": {"loggingLevel": "ERROR"},
			}],
		},
	]}}]}}

	# the logging level is set to INFO or ERROR for all API Gateway stages
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"__typename": "AWSAPIGatewayRestAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aaa",
				"displayName": "rest-api-test-1",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {"loggingLevel": ""},
				}],
			}],
		},
		{
			"__typename": "AWSAPIGatewayRestAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aab",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {"loggingLevel": "OFF"},
				}],
			}],
		},
		{
			"__typename": "AWSAPIGatewayRestAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ntbbb",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [],
		},
		{
			"__typename": "AWSAPIGatewayWebSocketAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|websocket|2sebg6qccc",
				"displayName": "websocket-api-test-5",
			},
			"stages": [
				{
					"name": "teststage",
					"defaultRouteSettings": {"loggingLevel": ""},
				},
				{
					"name": "teststage-2",
					"defaultRouteSettings": {"loggingLevel": "INFO"},
				},
			],
		},
		{
			"__typename": "AWSAPIGatewayWebSocketAPI",
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|websocket|2sebg6qddd",
				"displayName": "websocket-api-test-7",
			},
			"stages": [{
				"name": "teststage",
				"defaultRouteSettings": {"loggingLevel": "OFF"},
			}],
		},
	]}}]}}
}
