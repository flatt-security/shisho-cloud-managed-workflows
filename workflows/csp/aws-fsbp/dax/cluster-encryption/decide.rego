package policy.aws.dax.cluster_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.dynamoDb.clusters[_]

	enabled := cluster.sseDescription.status == "ENABLED"

	d := shisho.decision.aws.dax.cluster_encryption({
		"allowed": allow_if_excluded(enabled, cluster),
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.dax.cluster_encryption_payload({"enabled": enabled}),
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
