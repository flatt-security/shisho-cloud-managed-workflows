package policy.aws.iam.key_rotation

import data.shisho

# This policy checks if the access keys are used within 3 months
# please adjust the `days_of_accepted_age` variable depending on your needs
days_of_accepted_age := 90

decisions[d] {
	account := input.aws.accounts[_]
	user := account.iam.users[_]

	keys := keys_requiring_rotation(user.accessKeys)
	trace(sprintf("name=%v", [keys]))
	allowed := count(keys) == 0

	d := shisho.decision.aws.iam.key_rotation({
		"allowed": allow_if_excluded(allowed, user),
		"subject": user.metadata.id,
		"payload": shisho.decision.aws.iam.key_rotation_payload({
			"keys_requiring_rotation": keys,
			"recommended_rotation_window_days": days_of_accepted_age,
		}),
	})
}

keys_requiring_rotation(keys) := x {
	count(keys) > 0

	x := [{
		"id": key.id,
		"created_at": key.createdAt,
	} |
		key := keys[_]
		needs_rotation(key)
	]
} else := []

# the key needs rotation...
needs_rotation(key) {
	# (1) if the key has never been used, and `days_of_accepted_age` days have passed since the key was created
	key.lastUsed == null
	now := time.now_ns()

	t := time.parse_rfc3339_ns(key.createdAt)
	now - t > (((1000000000 * 60) * 60) * 24) * days_of_accepted_age
} else {
	# (2) if the key has been used so far, and `days_of_accepted_age` days have passed since the key was used last
	key.lastUsed != null
	now := time.now_ns()

	t := time.parse_rfc3339_ns(key.lastUsed.lastUsedAt)
	now - t > (((1000000000 * 60) * 60) * 24) * days_of_accepted_age
} else = false

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
