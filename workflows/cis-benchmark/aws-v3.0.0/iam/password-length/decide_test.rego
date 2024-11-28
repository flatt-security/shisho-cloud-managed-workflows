package policy.aws.iam.password_length

import data.shisho
import future.keywords

test_whether_the_password_length_is_required_more_than_14_characters if {
	# check if the password length is required more than 14 characters
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"passwordPolicy": {"minimumPasswordLength": 16}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"passwordPolicy": {"minimumPasswordLength": 14}},
		},
	]}}

	# check if the password length is required more than 14 characters
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"passwordPolicy": {"minimumPasswordLength": 10}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"passwordPolicy": {"minimumPasswordLength": 4}},
		},
	]}}
}
