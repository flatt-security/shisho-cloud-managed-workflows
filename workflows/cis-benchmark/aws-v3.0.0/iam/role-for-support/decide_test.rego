package policy.aws.iam.role_for_support

import data.shisho
import future.keywords

test_whether_the_roles_is_created_for_aws_support if {
	# check if the role is created for AWS support
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779392177777",
				"displayName": "779392177777",
			},
			"iam": {"policies": [
				{
					"name": "AWSSupportAccess",
					"entities": {"roles": [{"name": "test-role-1"}]},
				},
				{
					"name": "AWSLambdaBasicExecutionRole-test-policy-name-2",
					"entities": {"roles": [{"name": "test-role-2"}]},
				},
			]},
		},
		{
			"metadata": {
				"id": "aws-account|779392188888",
				"displayName": "779392188888",
			},
			"iam": {"policies": [
				{
					"name": "AWSSupportAccess",
					"entities": {"roles": [{"name": "test-role-1"}]},
				},
				{
					"name": "AWSLambdaBasicExecutionRole-test-policy-name-2",
					"entities": {"roles": [{"name": "test-role-2"}]},
				},
			]},
		},
	]}}

	# check if the role is not created for AWS support
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779392177777",
				"displayName": "779392177777",
			},
			"iam": {"policies": [{
				"name": "AWSLambdaBasicExecutionRole-test-policy-name-2",
				"entities": {"roles": [{"name": "test-role-2"}]},
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779392188888",
				"displayName": "779392188888",
			},
			"iam": {"policies": [{
				"name": "AWSLambdaBasicExecutionRole-test-policy-name-2",
				"entities": {"roles": [{"name": "test-role-2"}]},
			}]},
		},
	]}}
}
