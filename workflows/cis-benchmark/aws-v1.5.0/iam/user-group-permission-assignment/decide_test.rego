package policy.aws.iam.user_group_permission_assignment

import data.shisho
import future.keywords

test_whether_the_user_has_policies_directly if {
	# check if the user does not have any policies directly
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZAAAAA",
				"displayName": "test-user-1",
			},
			"policies": [],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZBBBB",
				"displayName": "test-user-2",
			},
			"policies": [],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZCCCCC",
				"displayName": "test-user-3",
			},
			"policies": [],
		},
	]}}]}}

	# check if the user has some policies directly
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZAAAAA",
				"displayName": "test-user-1",
			},
			"policies": [{"name": "test-user-policy-1"}, {"name": "test-user-policy-1-2"}],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZBBBB",
				"displayName": "test-user-2",
			},
			"policies": [{"name": "test-user-policy-2"}],
		},
		{
			"metadata": {
				"id": "aws-iam-user|AIDA3K53E734T6EZCCCCC",
				"displayName": "test-user-3",
			},
			"policies": [{"name": "test-user-policy-3"}],
		},
	]}}]}}
}
