package policy.aws.secretsmanager.auto_rotation_state

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

two_days_ago_string := date_string(time.add_date(now_ns, 0, 0, -2))

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
	]) == 4 with input as {"aws": {"accounts": [{"secretsManager": {"secrets": [
		# The rotation is not enabled so this check is unnecessary
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-1",
				"displayName": "test-secret-1",
			},
			"region": "ap-northeast-1",
			"primaryRegion": "",
			"rotationEnabled": false,
			"createdAt": today_string,
			"lastRotatedAt": null,
			"rotationRules": null,
		},
		# A replica secret with healthy rotation
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"region": "ap-northeast-1",
			"primaryRegion": "ap-northeast-2", # different primary region
			"rotationEnabled": true,
			"createdAt": two_days_ago_string,
			"lastRotatedAt": today_string,
			"rotationRules": {
				"automaticallyAfterDays": 1,
				"scheduleExpression": "cron(0 0 ? 1/3 2#1 *)",
			},
		},
		# A replica secret with unhealthy rotation
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"region": "ap-northeast-2",
			"primaryRegion": "ap-northeast-1",
			"rotationEnabled": true,
			"createdAt": two_days_ago_string,
			"lastRotatedAt": two_days_ago_string,
			"rotationRules": {
				"automaticallyAfterDays": 1,
				"scheduleExpression": "cron(0 0 ? 1/3 2#1 *)",
			},
		},
		# Non replica secret but rotation is ongoing successfully
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-southeast-1|test-secret-3",
				"displayName": "test-secret-3",
			},
			"region": "ap-northeast-1",
			"primaryRegion": "ap-northeast-1",
			"rotationEnabled": true,
			"createdAt": two_days_ago_string,
			"lastRotatedAt": null,
			"rotationRules": {
				"automaticallyAfterDays": 7,
				"scheduleExpression": "cron(0 0 ? 1/3 2#1 *)",
			},
		},
	]}}]}}
}

test_rotation_state_for_secrets_manager_secrets_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"secretsManager": {"secrets": [
		# should be denied because it is not rotated at all
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-southeast-2|test-secret-2",
				"displayName": "test-secret-2",
			},
			"region": "ap-southeast-1",
			"primaryRegion": "ap-southeast-1",
			"rotationEnabled": true,
			"createdAt": two_days_ago_string,
			"lastRotatedAt": null,
			"rotationRules": {
				"automaticallyAfterDays": 1,
				"scheduleExpression": "cron(0 0 ? 1/3 2#1 *)",
			},
		},
		# should be denied because it is not rotated for a day
		{
			"metadata": {
				"id": "aws-secretsmanager-secret|ap-northeast-1|test-secret-2",
				"displayName": "test-secret-2",
			},
			"region": "ap-northeast-1",
			"primaryRegion": "ap-northeast-1",
			"rotationEnabled": true,
			"createdAt": two_days_ago_string,
			"lastRotatedAt": two_days_ago_string,
			"rotationRules": {
				"automaticallyAfterDays": 1,
				"scheduleExpression": "cron(0 0 ? 1/3 2#1 *)",
			},
		},
	]}}]}}
}
