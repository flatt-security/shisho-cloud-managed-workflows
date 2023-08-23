package policy.aws.iam.key_rotation

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

four_months_ago_string := date_string(time.add_date(now_ns, 0, -4, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

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

	# check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"iam": {"users": [
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
			"tags": [{"key": "foo", "value": "bar=piyo"}],
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
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
