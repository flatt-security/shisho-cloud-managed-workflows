package policy.aws.dynamodb.table_point_in_time_recovery

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	table := account.dynamoDb.tables[_]

	enabled := table.continuousBackupsDescription.pointInTimeRecoveryDescription.status == "ENABLED"

	d := shisho.decision.aws.dynamodb.table_point_in_time_recovery({
		"allowed": allow_if_excluded(enabled, table),
		"subject": table.metadata.id,
		"payload": shisho.decision.aws.dynamodb.table_point_in_time_recovery_payload({"enabled": enabled}),
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
