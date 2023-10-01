package policy.googlecloud.iam.service_account_key_rotation

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

six_months_ago_string := date_string(time.add_date(now_ns, 0, -5, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_whether_keys_of_service_accounts_are_rotated if {
	# check if the keys of service accounts are rotated within `must_alert_if_not_rotated_for`
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"iam": {"serviceAccounts": [
		{
			"metadata": {"id": "googlecloud-iam-sa|514897777777|112977612696787777777"},
			"name": "projects/test-project-1/serviceAccounts/test-sa-1@test-project-1.iam.gserviceaccount.com",
			"keys": [
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-1@test-project-1.iam.gserviceaccount.com/keys/0727440ed4a7f0f11cd8fdedae9c8c8fdc78fc60",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": today_string,
				},
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-1@test-project-1.iam.gserviceaccount.com/keys/44b9920dd7a8b1e94ef46774406c210d2e179a69",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": today_string,
				},
			],
		},
		{
			"metadata": {"id": "googlecloud-iam-sa|514898888888|113958550370488888888"},
			"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com",
			"keys": [
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com/keys/148eb84058a3c0d02f42615842fda072d3512f26",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": today_string,
				},
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com/keys/fce2154a4ec3f69714053cd725e6a3ef4851ec09",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "SYSTEM_MANAGED",
					"validAfterAt": six_months_ago_string,
				},
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com/keys/148eb84058a3c0d02f42615842fda072d3512f26",
					"disabled": true,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": six_months_ago_string,
				},
			],
		},
	]}}]}}

	# check if the keys of service accounts are not rotated within `must_alert_if_not_rotated_for`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"iam": {"serviceAccounts": [
		{
			"metadata": {"id": "googlecloud-iam-sa|514897777777|112977612696787777777"},
			"name": "projects/test-project-1/serviceAccounts/test-sa-1@test-project-1.iam.gserviceaccount.com",
			"keys": [
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-1@test-project-1.iam.gserviceaccount.com/keys/0727440ed4a7f0f11cd8fdedae9c8c8fdc78fc60",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": six_months_ago_string,
				},
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-1@test-project-1.iam.gserviceaccount.com/keys/44b9920dd7a8b1e94ef46774406c210d2e179a69",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": six_months_ago_string,
				},
			],
		},
		{
			"metadata": {"id": "googlecloud-iam-sa|514898888888|113958550370488888888"},
			"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com",
			"keys": [
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com/keys/148eb84058a3c0d02f42615842fda072d3512f26",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": six_months_ago_string,
				},
				{
					"name": "projects/test-project-1/serviceAccounts/test-sa-2@test-project-1.iam.gserviceaccount.com/keys/fce2154a4ec3f69714053cd725e6a3ef4851ec09",
					"disabled": false,
					"origin": "USER_PROVIDED",
					"type": "USER_MANAGED",
					"validAfterAt": today_string,
				},
			],
		},
	]}}]}}
}
