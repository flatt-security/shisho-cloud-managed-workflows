package policy.aws.ecs.task_process_namespace

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	allowed := service.taskDefinition.pidMode != "HOST"

	d := shisho.decision.aws.ecs.task_process_namespace({
		"allowed": allow_if_excluded(allowed, service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.task_process_namespace_payload({"not_shared_namespace": allowed}),
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
