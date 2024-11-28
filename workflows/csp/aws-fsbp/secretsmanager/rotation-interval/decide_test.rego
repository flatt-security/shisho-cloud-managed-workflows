package policy.aws.secretsmanager.rotation_interval

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

six_months_ago_string := date_string(time.add_date(now_ns, 0, -6, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_rotation_state_for_secrets_manager_secrets_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"secretsManager": {"secrets": [
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-1",
				"displayName": "test-secret-1",
			},
			"createdAt": six_months_ago_string,
			"lastRotatedAt": today_string,
		},
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"createdAt": today_string,
			"lastRotatedAt": null,
		},
	]}}]}}
}

test_rotation_state_for_secrets_manager_secrets_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"secretsManager": {"secrets": [
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-1",
				"displayName": "test-secret-1",
			},
			"createdAt": six_months_ago_string,
			"lastRotatedAt": null,
		},
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"createdAt": six_months_ago_string,
			"lastRotatedAt": six_months_ago_string,
		},
	]}}]}}
}
