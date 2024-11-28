package policy.aws.apigateway.ssl_certificates

import data.shisho
import future.keywords

test_ssl_certificate_for_api_gateway_stages_is_enabled if {
	# the SSL certificate is enabled for all API Gateway stages
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
				"name": "test-stage",
				"clientCertificateId": "3jctaa",
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6nbbbb",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbcccc",
				"displayName": "rest-api-test-3",
			},
			"stages": [{
				"name": "test-stage",
				"clientCertificateId": "3jctbb",
			}],
		},
		{},
		{},
	]}}]}}

	# the SSL certificate is disbled for all API Gateway stages
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
					"name": "test-stage",
					"clientCertificateId": "3jctaa",
				},
				{
					"name": "test-stage-2",
					"clientCertificateId": "",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|u9tg6nbbbb",
				"displayName": "test-private-rest-api-3",
			},
			"stages": [],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynbcccc",
				"displayName": "rest-api-test-3",
			},
			"stages": [{
				"name": "test-stage",
				"clientCertificateId": "",
			}],
		},
		{},
		{},
	]}}]}}
}
