package policy.aws.iam.account_alternate_contact

import data.shisho
import future.keywords

test_whether_the_alternate_contact_of_accounts_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"alternateContactState": {
				"billingContactRegistered": true,
				"securityContactRegistered": true,
				"operationsContactRegistered": false,
			},
		},
		{
			"metadata": {
				"id": "aws-account|779397777778",
				"displayName": "779397777778",
			},
			"alternateContactState": {
				"billingContactRegistered": false,
				"securityContactRegistered": true,
				"operationsContactRegistered": false,
			},
		},
	]}}
}

test_whether_the_alternate_contact_of_accounts_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"alternateContactState": {
				"billingContactRegistered": true,
				"securityContactRegistered": false,
				"operationsContactRegistered": false,
			},
		},
		{
			"metadata": {
				"id": "aws-account|779397777778",
				"displayName": "779397777778",
			},
			"alternateContactState": {
				"billingContactRegistered": false,
				"securityContactRegistered": false,
				"operationsContactRegistered": false,
			},
		},
	]}}
}
