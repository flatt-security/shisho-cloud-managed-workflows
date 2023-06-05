package policy.aws.ecs.task

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	containers := service_container_privilege_configs(service)
	allowed := has_privileged_containers(containers) == false
	d := shisho.decision.aws.ecs.container_privilege({
		"allowed": allowed,
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

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	containers := service_container_filesystem_configs(service)
	allowed := has_writeable_root_fs(containers) == false
	d := shisho.decision.aws.ecs.container_fs_permission({
		"allowed": allowed,
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
