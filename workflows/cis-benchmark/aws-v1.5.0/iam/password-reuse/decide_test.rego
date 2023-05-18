package policy.aws.iam.password_reuse

import data.shisho
import future.keywords

test_whether_the_last_24_passowords_are_remembered if {
	# check if the last 24 passwords are remembered 
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"passwordPolicy": {"passwordReusePrevention": 24}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"passwordPolicy": {"passwordReusePrevention": 30}},
		},
	]}}

	# check if the last 24 passwords are not remembered 
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"passwordPolicy": {"passwordReusePrevention": 0}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"passwordPolicy": {"passwordReusePrevention": 10}},
		},
	]}}
}
