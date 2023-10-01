package policy.googlecloud.kms.key_rotation

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

test_whether_kms_keys_are_rotated if {
	# check if the KMS keys are rotated within `must_alert_if_not_rotated_for`
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"kms": {"keyRings": [
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|5148932577777|projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
				"displayName": "projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
			},
			"rotationPeriod": 7776000,
			"nextRotatedAt": today_string,
		}]},
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|5148932577777|projects/test-project-1/locations/us-west1/keyRings/test-keyring-2/cryptoKeys/test-key-2",
				"displayName": "projects/test-project-1/locations/us-west1/keyRings/test-keyring-2/cryptoKeys/test-key-2",
			},
			"rotationPeriod": 1728000,
			"nextRotatedAt": today_string,
		}]},
	]}}]}}

	# check if the KMS keys are not rotated within `must_alert_if_not_rotated_for`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"kms": {"keyRings": [
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|5148932577777|projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
				"displayName": "projects/test-project-1/locations/asia-northeast1/keyRings/test-keyring-3/cryptoKeys/test-key-3",
			},
			"rotationPeriod": 7776000,
			"nextRotatedAt": six_months_ago_string,
		}]},
		{"keys": [{
			"metadata": {
				"id": "googlecloud-kms-key|5148932577777|projects/test-project-1/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
				"displayName": "projects/test-project-1/locations/global/keyRings/test-keyring/cryptoKeys/test-key",
			},
			"rotationPeriod": 31104000,
			"nextRotatedAt": today_string,
		}]},
	]}}]}}
}
