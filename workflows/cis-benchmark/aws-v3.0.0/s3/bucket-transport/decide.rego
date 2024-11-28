package policy.aws.s3.bucket_transport

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	allowed := has_secure_transport_policy(bucket.policy.rawDocument)
	d := shisho.decision.aws.s3.bucket_transport({
		"allowed": allow_if_excluded(allowed, bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_transport_payload({"is_http_denied": allowed}),
	})
}

has_secure_transport_policy(raw_document) {
	policy_data := json.unmarshal(raw_document)

	statement := policy_data.Statement[_]
	statement.Effect == "Deny"
	startswith(statement.Action, "s3:")
	bool_condition := statement.Condition.Bool
	config_value := object.filter(bool_condition, ["aws:SecureTransport"])

	# check if the value is false
	# the key "aws:SecureTransport" might have a string value or an array of string values
	contains(json.marshal(config_value), "false")
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
