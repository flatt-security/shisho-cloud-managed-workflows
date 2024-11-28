package policy.aws.cloudtrail.cloudwatch_logs_integration

import data.shisho

# this policy checks if the CloudWatch has not logged within the last 1 day
# please adjust the `must_alert_if_not_log_for` variable depending on your needs
must_alert_if_not_log_for := 1

decisions[d] {
	account := input.aws.accounts[_]
	trail := account.cloudTrail.trails[_]

	allowed := has_logs_within_recent_days(trail)
	d := shisho.decision.aws.cloudtrail.cloudwatch_logs_integration({
		"allowed": allow_if_excluded(allowed, trail),
		"subject": trail.metadata.id,
		"payload": shisho.decision.aws.cloudtrail.cloudwatch_logs_integration_payload({"integrated": allowed}),
	})
}

has_logs_within_recent_days(trail) {
	trail.status.latestCloudWatchLogsDeliveredAt == null
} else {
	# There is a log group associated with the trail
	trail.cloudWatchLogGroup.arn != ""

	# The log delivery is still active within the specified days
	lat := timestamp_ns(trail.status.latestCloudWatchLogsDeliveredAt)
	logged_within_recent_days(lat, must_alert_if_not_log_for)
} else = false

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

logged_within_recent_days(ts, d) {
	now := time.now_ns()
	diff_ns := now - ts

	# confirm the difference is less than `d` days
	diff_ns < (((1000000000 * 60) * 60) * 24) * d
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
