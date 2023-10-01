package policy.googlecloud.iam.service_account_key_rotation

import data.shisho

# this policy checks if the key are rotated within the last 90 days
# please adjust the `must_alert_if_not_rotated_for` variable depending on your needs
must_alert_if_not_rotated_for := 45

decisions[d] {
	project := input.googleCloud.projects[_]
	account := project.iam.serviceAccounts[_]

	keys := user_managed_keys(account.keys)
	allowed := count(keys) == 0

	d := shisho.decision.googlecloud.iam.service_account_key_rotation({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.googlecloud.iam.service_account_key_rotation_payload({"keys": keys}),
	})
}

user_managed_keys(keys) := x {
	x := [{"name": key.name, "valid_after_at": key.validAfterAt} |
		key := keys[_]
		key.type == "USER_MANAGED"
		key.disabled == false
		lat := timestamp_ns(key.validAfterAt)
		rotated_within_recent_days(lat, must_alert_if_not_rotated_for)
	]
}

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

rotated_within_recent_days(ts, d) {
	now := time.now_ns()

	diff_ns := now - ts

	# True if the difference is greater than `d` days
	diff_ns > (((1000000000 * 60) * 60) * 24) * d
} else = false
