package policy.aws.iam.credentials_inventory

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

two_months_ago_string := date_string(time.add_date(now_ns, 0, -2, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_whether_the_user_or_access_key_are_used_within_45_days if {
	# check if the users are created within 45 days
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": today_string,
			"passwordLastUsedAt": null,
			"accessKeys": [],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": today_string,
			"passwordLastUsedAt": null,
			"accessKeys": [],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73CCCCCCCCCC"},
			"createdAt": today_string,
			"passwordLastUsedAt": null,
			"accessKeys": [],
		},
	]}}]}}

	# check if the user's passwords are used within 45 days
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": today_string,
			"accessKeys": [],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": today_string,
			"accessKeys": [],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73CCCCCCCCCC"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": today_string,
			"accessKeys": [],
		},
	]}}]}}

	# check if the access keys are created within 45 days
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": today_string,
				"lastUsed": null,
			}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": today_string,
				"lastUsed": null,
			}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73CCCCCCCCCC"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": today_string,
				"lastUsed": null,
			}],
		},
	]}}]}}

	# check if the access keys are used within 45 days
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": two_months_ago_string,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": today_string},
			}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": two_months_ago_string,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": today_string},
			}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73CCCCCCCCCC"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": two_months_ago_string,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": today_string},
			}],
		},
	]}}]}}

	# check if the users is not created within 45 days
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [],
		},
	]}}]}}

	# check if the user's passwords are not used within 45 days
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": two_months_ago_string,
			"accessKeys": [],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": two_months_ago_string,
			"accessKeys": [],
		},
	]}}]}}

	# check if the access key is not created within 45 days
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": null,
			}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": null,
			}],
		},
	]}}]}}

	# check if the access key is not used within 45 days
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": two_months_ago_string},
			}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": two_months_ago_string},
			}],
		},
	]}}]}}

	# check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": two_months_ago_string},
			}],
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"createdAt": two_months_ago_string,
			"passwordLastUsedAt": null,
			"accessKeys": [{
				"createdAt": two_months_ago_string,
				"lastUsed": {"lastUsedAt": two_months_ago_string},
			}],
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
