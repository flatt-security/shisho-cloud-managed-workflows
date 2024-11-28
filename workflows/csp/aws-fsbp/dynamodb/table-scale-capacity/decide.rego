package policy.aws.dynamodb.table_scale_capacity

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	table := account.dynamoDb.tables[_]

	enabled := autoscaling_status(table)

	d := shisho.decision.aws.dynamodb.table_scale_capacity({
		"allowed": allow_if_excluded(enabled, table),
		"subject": table.metadata.id,
		"payload": shisho.decision.aws.dynamodb.table_scale_capacity_payload({
			"autoscaling_enabled": enabled,
			"billing_mode": table.billingModeSummary.mode,
			"read_capacity": table.provisionedThroughput.readCapacityUnits,
			"write_capacity": table.provisionedThroughput.writeCapacityUnits,
		}),
	})
}

autoscaling_status(table) {
	[
		table.billingModeSummary.mode == "PAY_PER_REQUEST",
		capacityUnits(table.provisionedThroughput),
	][_] == true
} else = false

capacityUnits(provisioned_throughput) {
	provisioned_throughput.readCapacityUnits > 0
	provisioned_throughput.writeCapacityUnits > 0
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
