package policy.aws.lambda.public_access

import data.shisho
import future.keywords

test_public_access_for_lambda_functions_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"lambda": {"functions": [
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-1",
				"displayName": "test-function-1",
			},
			"policy": {"rawPolicy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"test-sid-1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"apigateway.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:779397777777:function:test-1\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:sns:ap-northeast-1:test-1\"}}}]}"},
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-5",
				"displayName": "test-function-5",
			},
			"policy": {"rawPolicy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"test-sid-5\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"apigateway.amazonaws.com\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:779397777777:function:test-5\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:sns:ap-northeast-1:test-5\"}}}]}"},
		},
	]}}]}}
}

test_public_access_for_lambda_functions_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"lambda": {"functions": [
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-1",
				"displayName": "test-function-1",
			},
			"policy": {"rawPolicy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"test-sid-1\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:779397777777:function:test-1\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:sns:ap-northeast-1:test-1\"}}}]}"},
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-2",
				"displayName": "test-function-2",
			},
			"policy": {"rawPolicy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"test-sid-2\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:779397777777:function:test-2\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:sns:ap-northeast-1:test-2\"}}}]}"},
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-3",
				"displayName": "test-function-3",
			},
			"policy": {"rawPolicy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"test-sid-3\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:779397777777:function:test-3\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:sns:ap-northeast-1:test-3\"}}}]}"},
		},
		{
			"metadata": {
				"id": "aws-lambda-function|ap-northeast-1|test-function-4",
				"displayName": "test-function-4",
			},
			"policy": {"rawPolicy": "{\"Version\":\"2012-10-17\",\"Id\":\"default\",\"Statement\":[{\"Sid\":\"test-sid-4\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"*\"]},\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"arn:aws:lambda:ap-northeast-1:779397777777:function:test-4\",\"Condition\":{\"ArnLike\":{\"AWS:SourceArn\":\"arn:aws:sns:ap-northeast-1:test-4\"}}}]}"},
		},
	]}}]}}
}
