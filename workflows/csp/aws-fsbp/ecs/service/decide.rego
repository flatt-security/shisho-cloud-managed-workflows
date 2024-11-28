package policy.aws.ecs.service

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.ecs.clusters[_]
	service := cluster.services[_]

	allowed := service_has_automatic_ip_assignment(service) == false
	d := shisho.decision.aws.ecs.service_public_ip({
		"allowed": allow_if_excluded(allowed, service),
		"subject": service.metadata.id,
		"payload": shisho.decision.aws.ecs.service_public_ip_payload({
			"public_ip_assigned": service_public_assignment(service),
			"security_groups": service_sgs(service),
			"subnets": service_subnets(service),
		}),
		"severity": custom_severity(service),
	})
}

service_runs_on_fargate(s) {
	s.launchType != null
	s.launchType == "FARGATE"
} else {
	str := s.capacityProviderStrategy[_]
	str.name == "FARGATE"
} else {
	str := s.capacityProviderStrategy[_]
	str.name == "FARGATE_SPOT"
} else := false

custom_severity(s) := shisho.decision.severity_info {
	not service_runs_on_fargate(s)
} else := null

service_has_automatic_ip_assignment(s) {
	s.networkConfiguration != null
	s.networkConfiguration.vpcConfiguration != null
	s.networkConfiguration.vpcConfiguration.assignPublicIp == "ENABLED"
} else := false

service_public_assignment(s) := s.networkConfiguration.vpcConfiguration.assignPublicIp {
	s.networkConfiguration != null
	s.networkConfiguration.vpcConfiguration != null
} else := "DISABLED"

service_sgs(s) := [sg.id | sg := s.networkConfiguration.vpcConfiguration.securityGroups[_]] {
	s.networkConfiguration != null
	s.networkConfiguration.vpcConfiguration != null
} else := []

service_subnets(s) := [sb.id | sb := s.networkConfiguration.vpcConfiguration.subnets[_]] {
	s.networkConfiguration != null
	s.networkConfiguration.vpcConfiguration != null
} else := []

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
