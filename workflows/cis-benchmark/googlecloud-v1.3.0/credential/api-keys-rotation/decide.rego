package policy.googlecloud.credential.api_keys_rotation

import data.shisho

# this policy checks if the API keys are created/rotated within the last 90 days
# please adjust the `must_alert_if_not_rotated_for` variable depending on your needs
must_alert_if_not_rotated_for := 90

decisions[d] {
	project := input.googleCloud.projects[_]
	api_key := project.credentials.apiKeys[_]
	api_key.deletedAt == null

	lat := timestamp_ns(api_key.createdAt)

	d := shisho.decision.googlecloud.credential.api_keys_rotation({
		"allowed": rotated_within_days(lat, must_alert_if_not_rotated_for),
		"subject": api_key.metadata.id,
		"payload": shisho.decision.googlecloud.credential.api_keys_rotation_payload({"created_at": api_key.createdAt}),
	})
}

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

rotated_within_days(ts, d) {
	now := time.now_ns()

	diff_ns := now - ts

	# True if the difference is less than `d` days
	diff_ns <= (((1000000000 * 60) * 60) * 24) * d
} else = false
