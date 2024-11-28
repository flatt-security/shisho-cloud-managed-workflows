package policy.aws.ecs.task_fargate_version

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	type := lauch_type(service)
	type == "FARGATE"

	d := shisho.decision.aws.ecs.task_fargate_version({
		"allowed": allow_if_excluded(service.platformVersion == "LATEST", service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.task_fargate_version_payload({"version": service.platformVersion}),
	})
}

lauch_type(service) = "FARGATE" {
	[
		service.launchType == "FARGATE",
		lauch_type_from_capacity_provider_strategy(service.capacityProviderStrategy),
	][_] == true
} else = service.launchType

lauch_type_from_capacity_provider_strategy(capacity_provider_strategy) {
	st := capacity_provider_strategy[_]
	st.name == "FARGATE"
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
