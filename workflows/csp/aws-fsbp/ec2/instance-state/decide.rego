package policy.aws.ec2.instance_state

import data.shisho
import future.keywords.in

# The number of days that the instance has been in the current state.
# please adjust this value to your needs
accepted_unused_instance_duration = 30

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.ec2.instances[_]
	instance.state.state in ["STOPPING", "STOPPED"]

	allowed := unused_within_specific_days(
		timestamp_ns(instance.stateTransitedAt),
		accepted_unused_instance_duration,
	)

	d := shisho.decision.aws.ec2.instance_state({
		"allowed": allow_if_excluded(allowed, instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.ec2.instance_state_payload({
			"state": instance.state.state,
			"state_transition_time": instance.stateTransitedAt,
		}),
	})
}

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

unused_within_specific_days(ts, d) {
	now := time.now_ns()

	diff_ns := now - ts

	# True if the difference is less than `d` days
	diff_ns <= (((1000000000 * 60) * 60) * 24) * d
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
