package policy.aws.iam.root_user_usage

import data.shisho
import future.keywords

now_ns := time.now_ns()

now := time.date(now_ns)

today_string := sprintf("%d-%s-%sT00:00:00Z", [now[0], get_month(now[1]), get_day(now[2])])

five_months_ago_ns := time.add_date(now_ns, 0, -5, -0)

five_months_ago := time.date(five_months_ago_ns)

five_months_ago_string := sprintf("%d-%s-%sT00:00:00Z", [five_months_ago[0], get_month(five_months_ago[1]), get_day(five_months_ago[2])])

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

test_whether_the_root_user_is_used if {
	# check if the root user is not used
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"credentialReport": {"contents": [{
				"arn": "arn:aws:iam::779392187777:root",
				"passwordLastUsedAt": null,
				"accessKey1LastUsedAt": null,
				"accessKey2LastUsedAt": null,
			}]}},
		},
		{
			"metadata": {"id": "aws-account|77939218555"},
			"iam": {"credentialReport": {"contents": [{
				"arn": "arn:aws:iam::77939218555:root",
				"passwordLastUsedAt": five_months_ago_string,
				"accessKey1LastUsedAt": null,
				"accessKey2LastUsedAt": null,
			}]}},
		},
		{
			"metadata": {"id": "aws-account|77939218666"},
			"iam": {"credentialReport": {"contents": [{
				"arn": "arn:aws:iam::77939218666:root",
				"passwordLastUsedAt": null,
				"accessKey1LastUsedAt": five_months_ago_string,
				"accessKey2LastUsedAt": null,
			}]}},
		},
		{
			"metadata": {"id": "aws-account|77939218999"},
			"iam": {"credentialReport": {"contents": [{
				"arn": "arn:aws:iam::77939218999:root",
				"passwordLastUsedAt": null,
				"accessKey1LastUsedAt": null,
				"accessKey2LastUsedAt": five_months_ago_string,
			}]}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"credentialReport": {"contents": [{
				"arn": "arn:aws:iam::779392188888:user/test-user",
				"passwordLastUsedAt": null,
				"accessKey1LastUsedAt": null,
				"accessKey2LastUsedAt": null,
			}]}},
		},
	]}}

	# check if the root user is used
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"credentialReport": {"contents": [
				{
					"arn": "arn:aws:iam::779392187777:root",
					"passwordLastUsedAt": today_string,
					"accessKey1LastUsedAt": null,
					"accessKey2LastUsedAt": null,
				},
				{
					"arn": "arn:aws:iam::779392187777:user/test-user-1",
					"passwordLastUsedAt": null,
					"accessKey1LastUsedAt": null,
					"accessKey2LastUsedAt": null,
				},
			]}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"credentialReport": {"contents": [
				{
					"arn": "arn:aws:iam::779392188888:root",
					"passwordLastUsedAt": null,
					"accessKey1LastUsedAt": null,
					"accessKey2LastUsedAt": today_string,
				},
				{
					"arn": "arn:aws:iam::779392188888:user/test-user-2",
					"passwordLastUsedAt": "2022-03-10T11:49:31Z",
					"accessKey1LastUsedAt": null,
					"accessKey2LastUsedAt": null,
				},
			]}},
		},
		{
			"metadata": {"id": "aws-account|779392199999"},
			"iam": {"credentialReport": {"contents": [
				{
					"arn": "arn:aws:iam::779392199999:root",
					"passwordLastUsedAt": null,
					"accessKey1LastUsedAt": today_string,
					"accessKey2LastUsedAt": null,
				},
				{
					"arn": "arn:aws:iam::779392199999:user/test-user-2",
					"passwordLastUsedAt": "2022-03-10T11:49:31Z",
					"accessKey1LastUsedAt": null,
					"accessKey2LastUsedAt": null,
				},
			]}},
		},
	]}}
}
