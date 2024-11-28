package policy.aws.apigateway.access_logging

import data.shisho
import future.keywords

test_access_logging_for_api_gateway_stages_is_enabled if {
	# the access logging is enabled for all API Gateway stages
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
				"accessLogSettings": {"destinationArn": "arn:aws:logs:ap-northeast-1:779392188153:log-group:test-log-group-1"},
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbbbbb",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-2",
				"accessLogSettings": {"destinationArn": "arn:aws:logs:ap-northeast-1:779392188153:log-group:test-log-group-2"},
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ncccc",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [
				{
					"name": "test-stage-1",
					"accessLogSettings": {"destinationArn": "arn:aws:logs:ap-northeast-1:779392188153:log-group:test-log-group-3"},
				},
				{
					"name": "test-stage-2",
					"accessLogSettings": {"destinationArn": "arn:aws:logs:ap-northeast-1:779392188153:log-group:test-log-group-4"},
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ndddd",
				"displayName": "test-private-rest-api-4",
			},
			"stages": [],
		},
		{},
		{},
	]}}]}}

	# the access logging is not enabled for all API Gateway stages
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbaaaa",
				"displayName": "rest-api-test-2",
			},
			"stages": [
				{
					"name": "test-stage-1",
					"accessLogSettings": {"destinationArn": "arn:aws:logs:ap-northeast-1:779392188153:log-group:test-log-group-1"},
				},
				{
					"name": "test-stage-2",
					"accessLogSettings": null,
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbbbbb",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage-3",
				"accessLogSettings": null,
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ncccc",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [
				{
					"name": "test-stage-1",
					"accessLogSettings": {"destinationArn": "arn:aws:logs:ap-northeast-1:779392188153:log-group:test-log-group-2"},
				},
				{
					"name": "test-stage-2",
					"accessLogSettings": null,
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6ndddd",
				"displayName": "test-private-rest-api-4",
			},
			"stages": [],
		},
		{},
		{},
	]}}]}}
}
