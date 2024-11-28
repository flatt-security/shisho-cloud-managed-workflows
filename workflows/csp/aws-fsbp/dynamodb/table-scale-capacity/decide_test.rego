package policy.aws.dynamodb.table_scale_capacity

import data.shisho
import future.keywords

test_scale_capacity_for_dynamodb_tables_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"dynamoDb": {"tables": [
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|9722cc57-6763-47fb-ad6e-87537bb9ff1a",
				"displayName": "test-dynamodb-1",
			},
			"billingModeSummary": {"mode": "PAY_PER_REQUEST"},
			"provisionedThroughput": {
				"readCapacityUnits": 0,
				"writeCapacityUnits": 0,
			},
		},
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|56dd808b-83ee-4c05-85e7-bb9eaf94e31a",
				"displayName": "test-table-1",
			},
			"billingModeSummary": {"mode": "PROVISIONED"},
			"provisionedThroughput": {
				"readCapacityUnits": 1,
				"writeCapacityUnits": 1,
			},
		},
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-2|9158d548-48fe-46b1-977d-a47cbab850e0",
				"displayName": "test-table-1",
			},
			"billingModeSummary": {"mode": "PROVISIONED"},
			"provisionedThroughput": {
				"readCapacityUnits": 1,
				"writeCapacityUnits": 1,
			},
		},
	]}}]}}
}

test_scale_capacity_for_dynamodb_tables_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"dynamoDb": {"tables": [
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|9722cc57-6763-47fb-ad6e-87537bb9ff1a",
				"displayName": "test-dynamodb-1",
			},
			"billingModeSummary": {"mode": "PROVISIONED"},
			"provisionedThroughput": {
				"readCapacityUnits": 0,
				"writeCapacityUnits": 0,
			},
		},
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|56dd808b-83ee-4c05-85e7-bb9eaf94e31a",
				"displayName": "test-table-1",
			},
			"billingModeSummary": {"mode": "PROVISIONED"},
			"provisionedThroughput": {
				"readCapacityUnits": 0,
				"writeCapacityUnits": 0,
			},
		},
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-2|9158d548-48fe-46b1-977d-a47cbab850e0",
				"displayName": "test-table-1",
			},
			"billingModeSummary": {"mode": "PROVISIONED"},
			"provisionedThroughput": {
				"readCapacityUnits": 0,
				"writeCapacityUnits": 0,
			},
		},
	]}}]}}
}
