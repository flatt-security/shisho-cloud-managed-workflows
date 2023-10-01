package policy.googlecloud.kms.key_rotation

import data.shisho

# this policy checks if the KMS keys are rotated within the last 90 days
# please adjust the `must_alert_if_not_rotated_for` variable depending on your needs
threshould_days := 90

threshould_seconds := ((60 * 60) * 24) * threshould_days

decisions[d] {
	project := input.googleCloud.projects[_]
	key_ring := project.kms.keyRings[_]
	key := key_ring.keys[_]

	d := shisho.decision.googlecloud.kms.key_rotation({
		"allowed": is_rotated(key),
		"subject": key.metadata.id,
		"payload": shisho.decision.googlecloud.kms.key_rotation_payload({
			"rotation_period_seconds": key.rotationPeriod,
			"rotation_period_expectation_seconds": threshould_seconds,
			"last_rotated_at": key.nextRotatedAt,
		}),
	})
}

is_rotated(key) {
	key.rotationPeriod <= threshould_seconds
	lat := timestamp_ns(key.nextRotatedAt)
	last_rotation_within(lat, threshould_days)
} else = false

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

last_rotation_within(ts, d) {
	now := time.now_ns()

	diff_ns := now - ts

	# True if the difference is less than `d` days
	diff_ns <= (((1000000000 * 60) * 60) * 24) * d
} else = false
