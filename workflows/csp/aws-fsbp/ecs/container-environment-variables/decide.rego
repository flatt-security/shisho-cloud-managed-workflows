package policy.aws.ecs.container_environment_variables

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	containers := [{"name": container.name, "environment_variables": names} |
		container := service.taskDefinition.containerDefinitions[_]
		names := [container.environment[_].name |
			env_names := container.environment[_]
		]
	]

	d := shisho.decision.aws.ecs.container_environment_variables({
		"allowed": allow_if_excluded(not_used_environment_variables(containers), service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.container_environment_variables_payload({"containers": containers}),
	})
}

not_used_environment_variables(containers) = false {
	container := containers[_]
	variable := container.environment_variables[_]
	variable in [
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"ECS_ENGINE_AUTH_DATA",
	]
} else = true

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
