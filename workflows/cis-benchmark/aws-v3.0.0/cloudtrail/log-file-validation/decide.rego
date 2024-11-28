package policy.aws.cloudtrail.log_file_validation

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	trail := account.cloudTrail.trails[_]
	allowed := trail.logFileValidationEnabled

	d := shisho.decision.aws.cloudtrail.log_file_validation({
		"allowed": allow_if_excluded(allowed, trail),
		"subject": trail.metadata.id,
		"payload": shisho.decision.aws.cloudtrail.log_file_validation_payload({"enabled": allowed}),
	})
}

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
