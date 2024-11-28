package policy.aws.lambda.vpc_availability_zone

import data.shisho
import future.keywords

test_runtime_for_lambda_functions_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"lambda": {"functions": [
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-1",
				"displayName": "test-function-1",
			},
			"vpcConfiguration": {
				"subnetIds": [
					"subnet-test-1",
					"subnet-test-2",
				],
				"vpc": {"metadata": {
					"id": "aws-vpc|ap-northeast-1|test-vpc-1",
					"displayName": "test-vpc-1",
				}},
			},
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-2",
				"displayName": "test-function-2",
			},
			"vpcConfiguration": {
				"subnetIds": [
					"subnet-test-1",
					"subnet-test-2",
				],
				"vpc": {"metadata": {
					"id": "aws-vpc|ap-northeast-1|test-vpc-2",
					"displayName": "test-vpc-2",
				}},
			},
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-3",
				"displayName": "test-function-3",
			},
			"vpcConfiguration": {
				"subnetIds": [
					"subnet-test-1",
					"subnet-test-2",
				],
				"vpc": {"metadata": {
					"id": "aws-vpc|ap-northeast-1|test-vpc-3",
					"displayName": "test-vpc-3",
				}},
			},
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
			"vpcConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-2",
				"displayName": "test-function-2",
			},
			"vpcConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-3",
				"displayName": "test-function-3",
			},
			"vpcConfiguration": {
				"subnetIds": ["subnet-test-1"],
				"vpc": {"metadata": {
					"id": "aws-vpc|ap-northeast-1|test-vpc-1",
					"displayName": "test-vpc-1",
				}},
			},
		},
	]}}]}}
}
