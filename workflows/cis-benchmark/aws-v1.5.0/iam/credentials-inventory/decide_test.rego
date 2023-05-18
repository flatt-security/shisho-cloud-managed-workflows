package policy.aws.iam.credentials_inventory

import data.shisho
import future.keywords

now_ns := time.now_ns()

now := time.date(now_ns)

today_string := sprintf("%d-%s-%sT00:00:00Z", [now[0], get_month(now[1]), get_day(now[2])])

two_months_ago_ns := time.add_date(now_ns, 0, -2, -0)

two_months_ago := time.date(two_months_ago_ns)

two_months_ago_string := sprintf("%d-%s-%sT00:00:00Z", [two_months_ago[0], get_month(two_months_ago[1]), get_day(two_months_ago[2])])

get_month(month) = month_string if {
	month <= 10
	month_string := sprintf("0%d", [month])
} else = month_string if {
	month > 10
	month_string := sprintf("%d", [month])
}

get_day(day) := day_string if {
	day <= 10
	day_string := sprintf("0%d", [day])
} else := day_string if {
	day > 10
	day_string := sprintf("%d", [day])
}

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
}
