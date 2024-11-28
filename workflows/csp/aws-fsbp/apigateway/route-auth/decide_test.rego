package policy.aws.apigateway.route_auth

import data.shisho
import future.keywords

test_auth_for_api_gateway_routes_is_enabled if {
	# the authorization is configured for all API Gateway routes
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{},
		{},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|websocket|2sebgaaaaa",
				"displayName": "websocket-api-test-7",
			},
			"routes": [
				{
					"id": "4ymaaaa",
					"routeKey": "$connect",
					"authorizationType": "CUSTOM",
				},
				{
					"id": "7vraaaa",
					"routeKey": "$default",
					"authorizationType": "JWT",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|http|uk4jvbbbbb",
				"displayName": "http-api-test-1",
			},
			"routes": [{
				"id": "bwqbbbb",
				"routeKey": "ANY /test-function-1",
				"authorizationType": "CUSTOM",
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|http|uk4jvccccc",
				"displayName": "http-api-test-2",
			},
			"routes": [
				{
					"id": "3ifcccc",
					"routeKey": "GET /test-function",
					"authorizationType": "JWT",
				},
				{
					"id": "bwqcccc",
					"routeKey": "ANY /test-function-11",
					"authorizationType": "CUSTOM",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|http|uk4jvddddd",
				"displayName": "http-api-test-5",
			},
			"routes": [],
		},
	]}}]}}

	# the authorization is not configured for all API Gateway routes
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{},
		{},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|websocket|2sebgaaaaa",
				"displayName": "websocket-api-test-7",
			},
			"routes": [
				{
					"id": "0y8aaaa",
					"routeKey": "$disconnect",
					"authorizationType": "",
				},
				{
					"id": "4ymaaaa",
					"routeKey": "$connect",
					"authorizationType": "NONE",
				},
				{
					"id": "7vraaaa",
					"routeKey": "$default",
					"authorizationType": "JWT",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|http|uk4jvbbbbb",
				"displayName": "http-api-test-1",
			},
			"routes": [
				{
					"id": "3ifbbbb",
					"routeKey": "GET /test-function",
					"authorizationType": "NONE",
				},
				{
					"id": "bwqbbbb",
					"routeKey": "ANY /test-function-1",
					"authorizationType": "",
				},
				{
					"id": "g47bbbb",
					"routeKey": "GET /aaa",
					"authorizationType": "NONE",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|http|uk4jvccccc",
				"displayName": "http-api-test-2",
			},
			"routes": [
				{
					"id": "3ifcccc",
					"routeKey": "GET /test-function",
					"authorizationType": "NONE",
				},
				{
					"id": "bwqcccc",
					"routeKey": "ANY /test-function-11",
					"authorizationType": "CUSTOM",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|http|uk4jvddddd",
				"displayName": "http-api-test-5",
			},
			"routes": [],
		},
	]}}]}}
}
