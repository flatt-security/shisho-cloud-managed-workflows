package policy.aws.ecs.task_networking_mode

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	d := shisho.decision.aws.ecs.task_networking_mode({
		"allowed": allow_if_excluded(allowed(service), service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.task_networking_mode_payload({"network_mode": service.taskDefinition.networkMode}),
	})
}

allowed(service) {
	not service.taskDefinition.networkMode == "HOST"
} else := false

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
