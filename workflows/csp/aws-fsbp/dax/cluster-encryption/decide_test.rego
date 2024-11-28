package policy.aws.dax.cluster_encryption

import data.shisho
import future.keywords

test_scale_capacity_for_dynamodb_tables_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"dynamoDb": {"clusters": [
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|test-dax-cluster-1",
				"displayName": "test-dax-cluster-1",
			},
			"sseDescription": {"status": "ENABLED"},
		},
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|test-dax-cluster-2",
				"displayName": "test-dax-cluster-2",
			},
			"sseDescription": {"status": "ENABLED"},
		},
	]}}]}}
}

test_scale_capacity_for_dynamodb_tables_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"dynamoDb": {"clusters": [
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|test-dax-cluster-1",
				"displayName": "test-dax-cluster-1",
			},
			"sseDescription": {"status": "DISABLED"},
		},
		{
			"metadata": {
				"id": "aws-dynamodb-table|ap-northeast-1|test-dax-cluster-2",
				"displayName": "test-dax-cluster-2",
			},
			"sseDescription": {"status": "DISABLED"},
		},
	]}}]}}
}
