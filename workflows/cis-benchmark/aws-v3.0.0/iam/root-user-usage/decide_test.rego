package policy.aws.iam.root_user_usage

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

five_months_ago_string := date_string(time.add_date(now_ns, 0, -5, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

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
