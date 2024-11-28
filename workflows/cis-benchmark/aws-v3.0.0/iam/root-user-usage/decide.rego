package policy.aws.iam.root_user_usage

import data.shisho

# This policy checks if the root user is used within the last 1 days
# please adjust the `days_of_duration` variable depending on your needs
must_alert_if_used_in := 14

decisions[d] {
	account := input.aws.accounts[_]

	lat := last_used_at(account.iam.credentialReport.contents)
	used := used_within_recent_days(lat, must_alert_if_used_in)

	d := shisho.decision.aws.iam.root_user_usage({
		"allowed": used == false,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.root_user_usage_payload({"last_used_at": time.format(lat)}),
	})
}

last_used_at(contents) := x {
	content := contents[_]
	endswith(content.arn, ":root")

	x := max([
		timestamp_ns(content.passwordLastUsedAt),
		timestamp_ns(content.accessKey1LastUsedAt),
		timestamp_ns(content.accessKey2LastUsedAt),
	])
} else := 0

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

used_within_recent_days(ts, d) {
	now := time.now_ns()

	diff_ns := now - ts

	# True if the difference is less than `d` days
	diff_ns < (((1000000000 * 60) * 60) * 24) * d
} else = false
