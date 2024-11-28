package policy.aws.secretsmanager.auto_rotation_state

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	secret := account.secretsManager.secrets[_]

	d := shisho.decision.aws.secretsmanager.auto_rotation_state({
		"allowed": allow_if_excluded(is_allowed(secret), secret),
		"subject": secret.metadata.id,
		"payload": shisho.decision.aws.secretsmanager.auto_rotation_state_payload({
			"last_rotated_at": last_rotated_at(secret),
			"schedule_expression": schedule_expression(secret),
		}),
	})
}

last_rotated_at(secret) = secret.lastRotatedAt {
	secret.lastRotatedAt != null
} else := null

schedule_expression(secret) = secret.rotationRules.scheduleExpression {
	secret.rotationRules.scheduleExpression != null
} else := null

is_replica_secret(secret) {
	secret.primaryRegion != ""
	secret.region != secret.primaryRegion
} else = false

is_allowed(secret) {
	# if this is a replica secret, we don't want to check the rotation state
	is_replica_secret(secret)
} else {
	# if the rotation is not enabled, we don't want to check the rotation state
	not secret.rotationEnabled
} else {
	nrat := max([
		timestamp_ns(secret.createdAt),
		timestamp_ns(secret.lastRotatedAt),
	])

	rotated_within_specified_days(
		nrat,
		secret.rotationRules.automaticallyAfterDays,
	)
} else = false

rotated_within_specified_days(ts, d) {
	now := time.now_ns()

	# True if the difference is less than `ts`
	now - ts < (((1000000000 * 60) * 60) * 24) * d
} else = false

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
