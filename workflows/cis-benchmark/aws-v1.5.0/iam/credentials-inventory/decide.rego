package policy.aws.iam.credentials_inventory

import data.shisho

# this policy checks if the credentials are created/used within the last 45 days
# please adjust the `days_of_accepted_age` variable depending on your needs
must_alert_if_unused_for := 45

decisions[d] {
	account := input.aws.accounts[_]
	user := account.iam.users[_]

	# The last time the user was used
	lat := last_used_at(user)

	# Review whether or not the user is used within the last `must_alert_if_unused_for` days
	active := used_within_recent_days(lat, must_alert_if_unused_for)

	# if the user is active, the policy must allow it.
	allowed := active

	d := shisho.decision.aws.iam.credentials_inventory({
		"allowed": allowed,
		"subject": user.metadata.id,
		"payload": shisho.decision.aws.iam.credentials_inventory_payload({
			"last_used_at": time.format(lat),
			"recommended_grace_period_days": must_alert_if_unused_for,
		}),
	})
}

# The last timestamp a user was used
last_used_at(user) := x {
	# -> The timestamp will be the max of the following:	
	x := max([
		# The timestamp the user was created
		timestamp_ns(user.createdAt),
		# The timestamp the user's password was last used
		timestamp_ns(user.passwordLastUsedAt),
		# The timestamp the user's access keys were last used
		keys_last_used_at(user),
	])
} else := 0 {
	true
}

# The last timestamp a user's access keys were used
keys_last_used_at(user) := x {
	count(user.accessKeys) > 0
	x := max([key_last_used_at(key) | key := user.accessKeys[_]])
} else := 0 {
	true
}

# The last timestamp an access key was used
key_last_used_at(key) := x {
	key.lastUsed == null
	x := timestamp_ns(key.createdAt)
} else := x {
	key.lastUsed != null
	x := max([
		timestamp_ns(key.createdAt),
		timestamp_ns(key.lastUsed.lastUsedAt),
	])
} else := 0 {
	true
}

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t) {
	true
}

used_within_recent_days(ts, d) {
	now := time.now_ns()

	diff_ns := now - ts

	# True if the difference is less than `d` days
	diff_ns < (((1000000000 * 60) * 60) * 24) * d
} else = false {
	true
}
