package policy.googlecloud.credential.api_keys_rotation

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

test_whether_api_keys_are_rotated if {
	# check if the API keys are rotated within `must_alert_if_not_rotated_for`
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"credentials": {"apiKeys": [{
				"metadata": {
					"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428faca562a",
					"displayName": "test key 1",
				},
				"deletedAt": null,
				"createdAt": today_string,
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"credentials": {"apiKeys": [
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|514898888888|47bf78cc-9c32-42c6-a541-d428f8888888",
						"displayName": "test key 2",
					},
					"deletedAt": null,
					"createdAt": today_string,
				},
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|51489999999|47bf78cc-9c32-42c6-a541-d428f9999999",
						"displayName": "test key 3",
					},
					"deletedAt": six_months_ago_string,
					"createdAt": six_months_ago_string,
				},
			]},
		},
	]}}

	# check if the API keys are rotated within `must_alert_if_not_rotated_for`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"credentials": {"apiKeys": [{
				"metadata": {
					"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428faca562a",
					"displayName": "test key 1",
				},
				"deletedAt": null,
				"createdAt": six_months_ago_string,
			}]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"credentials": {"apiKeys": [
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|514898888888|47bf78cc-9c32-42c6-a541-d428f8888888",
						"displayName": "test key 2",
					},
					"deletedAt": null,
					"createdAt": six_months_ago_string,
				},
				{
					"metadata": {
						"id": "googlecloud-cre-api-key|51489999999|47bf78cc-9c32-42c6-a541-d428f9999999",
						"displayName": "test key 3",
					},
					"deletedAt": null,
					"createdAt": six_months_ago_string,
				},
			]},
		},
	]}}
}
