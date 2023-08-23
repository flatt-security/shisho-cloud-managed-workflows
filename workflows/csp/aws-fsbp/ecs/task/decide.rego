package policy.aws.ecs.task

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	containers := service_container_privilege_configs(service)
	allowed := has_privileged_containers(containers) == false
	d := shisho.decision.aws.ecs.container_privilege({
		"allowed": allow_if_excluded(allowed, service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.container_privilege_payload({"containers": containers}),
	})
}

service_container_privilege_configs(s) := [{
	"privileged": c.privileged,
	"container_name": c.name,
} |
	c := s.taskDefinition.containerDefinitions[_]
]

has_privileged_containers(containers) {
	c := containers[_]
	c.privileged
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

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	containers := service_container_filesystem_configs(service)
	allowed := has_writeable_root_fs(containers) == false
	d := shisho.decision.aws.ecs.container_fs_permission({
		"allowed": allow_if_excluded(allowed, service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.container_fs_permission_payload({"containers": containers}),
	})
}

service_container_filesystem_configs(s) := [{
	"is_root_fs_readonly": c.readonlyRootFilesystem,
	"container_name": c.name,
} |
	c := s.taskDefinition.containerDefinitions[_]
]

has_writeable_root_fs(containers) {
	c := containers[_]
	not c.is_root_fs_readonly
} else := false
