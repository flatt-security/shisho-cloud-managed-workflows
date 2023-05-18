package policy.aws.s3.bucket_transport

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	allowed := is_allowed(bucket.policy.rawDocument)

	d := shisho.decision.aws.s3.bucket_transport({
		"allowed": allowed,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_transport_payload({"is_http_denied": allowed}),
	})
}

is_allowed(raw_document) {
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
