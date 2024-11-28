package policy.aws.lambda.runtime

import data.shisho
import future.keywords

test_runtime_for_lambda_functions_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"lambda": {"functions": [
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-1",
				"displayName": "test-function-1",
			},
			"packageType": "ZIP",
			"runtime": "PYTHON3_9",
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-2",
				"displayName": "test-function-2",
			},
			"packageType": "ZIP",
			"runtime": "GO1_X",
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-3",
				"displayName": "test-function-3",
			},
			"packageType": "IMAGE",
			"runtime": "GO1_X",
		},
	]}}]}}
}

test_runtime_for_lambda_functions_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"lambda": {"functions": [
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-1",
				"displayName": "test-function-1",
			},
			"packageType": "ZIP",
			"runtime": "PYTHON2_7",
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-2",
				"displayName": "test-function-2",
			},
			"packageType": "ZIP",
			"runtime": "PROVIDED_AL2",
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-3",
				"displayName": "test-function-3",
			},
			"packageType": "ZIP",
			"runtime": "RUBY2_5",
		},
	]}}]}}
}
