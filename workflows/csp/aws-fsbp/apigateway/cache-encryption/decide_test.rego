package policy.aws.apigateway.cache_encryption

import data.shisho
import future.keywords

test_cache_encryption_for_api_gateway_stages_is_enabled if {
	# the cache encryption is enabled for all API Gateway stages
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aaa",
				"displayName": "rest-api-test-1",
			},
			"stages": [
				{
					"name": "test-stage-1",
					"methodSettings": [{
						"key": "*/*",
						"value": {
							"cachingEnabled": false,
							"cacheDataEncrypted": false,
						},
					}],
				},
				{
					"name": "test-stage-2",
					"methodSettings": [{
						"key": "*/*",
						"value": {
							"cachingEnabled": true,
							"cacheDataEncrypted": true,
						},
					}],
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aab",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {
						"cachingEnabled": true,
						"cacheDataEncrypted": true,
					},
				}],
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aac",
				"displayName": "rest-api-test-3",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {
						"cachingEnabled": true,
						"cacheDataEncrypted": true,
					},
				}],
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aad",
				"displayName": "rest-api-test-3",
			},
			"stages": [],
		},
	]}}]}}

	# the cache encryption is not enabled for all API Gateway stages
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"apigateway": {"apis": [
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aaa",
				"displayName": "rest-api-test-1",
			},
			"stages": [
				{
					"name": "test-stage-1",
					"methodSettings": [{
						"key": "*/*",
						"value": {
							"cachingEnabled": false,
							"cacheDataEncrypted": false,
						},
					}],
				},
				{
					"name": "test-stage-2",
					"methodSettings": [{
						"key": "*/*",
						"value": {
							"cachingEnabled": true,
							"cacheDataEncrypted": false,
						},
					}],
				},
			],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aab",
				"displayName": "rest-api-test-2",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {
						"cachingEnabled": true,
						"cacheDataEncrypted": false,
					},
				}],
			}],
		},
		{
			"metadata": {
				"id": "aws-api-gateway-api|ap-northeast-1|rest|kxnynb9aac",
				"displayName": "rest-api-test-3",
			},
			"stages": [{
				"name": "test-stage",
				"methodSettings": [{
					"key": "*/*",
					"value": {
						"cachingEnabled": true,
						"cacheDataEncrypted": false,
					},
				}],
			}],
		},
	]}}]}}
}
