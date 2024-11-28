package policy.aws.s3.bucket_lifecycle_policy

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	rules := lifecycle_rules(bucket.lifecycleConfiguration)

	d := shisho.decision.aws.s3.bucket_lifecycle_policy({
		"allowed": allow_if_excluded(enabled_lifecycle_policy(rules), bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_lifecycle_policy_payload({"lifecycle_rules": rules}),
	})
}

enabled_lifecycle_policy(rules) {
	rule := rules[_]
	rule.status == "ENABLED"
} else = false

lifecycle_rules(config) := x {
	x := [{"id": rule.id, "status": rule.status} |
		config != null
		rule := config.rules[_]
	]
} else = []

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
