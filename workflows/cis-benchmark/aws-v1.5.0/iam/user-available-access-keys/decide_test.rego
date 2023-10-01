package policy.aws.iam.user_available_access_keys

import data.shisho
import future.keywords

test_whether_the_user_owns_multipl_available_access_keys if {
	# check if the user does not own multiple available access keys
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZAAAAA",
				"displayName": "test-user-1",
			},
			"accessKeys": [{
				"id": "AKIA3K53E7345EVAAAAA",
				"status": "ACTIVE",
			}],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZBBBB",
				"displayName": "test-user-2",
			},
			"accessKeys": [{
				"id": "AKIA3K53E7345EVBBBBB",
				"status": "ACTIVE",
			}],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZCCCCC",
				"displayName": "test-user-3",
			},
			"accessKeys": [{
				"id": "AKIA3K53E7345EVCCCCC",
				"status": "ACTIVE",
			}],
		},
	]}}]}}

	# check if the user owns multiple available access keys
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZAAAAA",
				"displayName": "test-user-1",
			},
			"accessKeys": [
				{
					"id": "AKIA3K53E7345EVAAAAA",
					"status": "ACTIVE",
				},
				{
					"id": "AKIA3K53E7345EVAAAA2",
					"status": "ACTIVE",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZBBBB",
				"displayName": "test-user-2",
			},
			"accessKeys": [
				{
					"id": "AKIA3K53E7345EVBBBBB",
					"status": "ACTIVE",
				},
				{
					"id": "AKIA3K53E7345EVBBBB2",
					"status": "ACTIVE",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZCCCCC",
				"displayName": "test-user-3",
			},
			"accessKeys": [
				{
					"id": "AKIA3K53E7345EVCCCCC",
					"status": "ACTIVE",
				},
				{
					"id": "AKIA3K53E7345EVCCCC2",
					"status": "ACTIVE",
				},
			],
		},
	]}}]}}
}
