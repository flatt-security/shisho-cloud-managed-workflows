package policy.aws.iam.key_rotation

import data.shisho
import future.keywords

now_ns := time.now_ns()

now := time.date(now_ns)

today_string := sprintf("%d-%s-%sT00:00:00Z", [now[0], get_month(now[1]), get_day(now[2])])

four_months_ago_ns := time.add_date(now_ns, 0, -4, -0)

four_months_ago := time.date(four_months_ago_ns)

four_months_ago_string := sprintf("%d-%s-%sT00:00:00Z", [four_months_ago[0], get_month(four_months_ago[1]), get_day(four_months_ago[2])])

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

test_whether_all_access_keys_are_rotated_within_90_days if {
	# check if all access keys are used or created within 90 days
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"accessKeys": [
				{
					"id": "1",
					"createdAt": today_string,
					"lastUsed": {"lastUsedAt": today_string},
				},
				{
					"id": "2",
					"createdAt": "2021-03-17T11:49:31Z",
					"lastUsed": {"lastUsedAt": today_string},
				},
			],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"accessKeys": [
				{
					"id": "1",
					"createdAt": today_string,
					"lastUsed": null,
				},
				{
					"id": "2",
					"createdAt": "2022-03-20T11:49:31Z",
					"lastUsed": {"lastUsedAt": today_string},
				},
			],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73CCCCCCCCCC"},
			"accessKeys": [],
		},
	]}}]}}

	# check if users have any access keys which are older than 90 days or not used for 90 days
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"iam": {"users": [
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73AAAAAAAAAA"},
			"accessKeys": [
				{
					"id": "1",
					"createdAt": "2021-03-17T11:49:31Z",
					"lastUsed": {"lastUsedAt": four_months_ago_string},
				},
				{
					"id": "2",
					"createdAt": "2021-03-17T11:49:31Z",
					"lastUsed": {"lastUsedAt": today_string},
				},
			],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73BBBBBBBBBB"},
			"accessKeys": [
				{
					"id": "1",
					"createdAt": four_months_ago_string,
					"lastUsed": null,
				},
				{
					"id": "2",
					"createdAt": "2021-03-17T11:49:31Z",
					"lastUsed": {"lastUsedAt": today_string},
				},
			],
		},
		{
			"metadata": {"id": "aws-iam-user|AIDA3K53E73CCCCCCCCCC"},
			"accessKeys": [
				{
					"id": "1",
					"createdAt": four_months_ago_string,
					"lastUsed": {"lastUsedAt": four_months_ago_string},
				},
				{
					"id": "2",
					"createdAt": today_string,
					"lastUsed": {"lastUsedAt": today_string},
				},
			],
		},
	]}}]}}
}
