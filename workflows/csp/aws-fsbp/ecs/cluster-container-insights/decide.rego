package policy.aws.ecs.cluster_container_insights

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]

	allowed := container_insights(cluster.settings)

	d := shisho.decision.aws.ecs.cluster_container_insights({
		"allowed": allow_if_excluded(allowed, cluster),
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.ecs.cluster_container_insights_payload({"container_insights_enabled": allowed}),
	})
}

container_insights(settings) {
	setting := settings[_]
	setting.name == "CONTAINERINSIGHTS"
	setting.value == "enabled"
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
