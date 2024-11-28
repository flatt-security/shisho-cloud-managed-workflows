package policy.aws.rds.cluster_backtracking

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.rds.clusters[_]

	# The backtracking is about the Aurora MySQL cluster only as of 2024.
	cluster.engine == "AURORA_MYSQL"

	d := shisho.decision.aws.rds.cluster_backtracking({
		"allowed": allow_if_excluded(cluster.backtrackWindow >= 3600, cluster), # the minimum is 1 hour (3600 seconds)
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.rds.cluster_backtracking_payload({"backtrack_window_seconds": cluster.backtrackWindow}),
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
