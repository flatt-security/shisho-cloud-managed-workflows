package policy.googlecloud.compute.instance_public_ip

import data.shisho

# CIS Google Cloud Platform Foundation Benchmark v1.3.0 describes that the GKE nodes should be excluded.
#
# However, there is less logical reason to have exception, and Google Cloud also recommends to set a minimum role:
# https://cloud.google.com/kubernetes-engine/docs/how-to/service-accounts?hl=ja#default-gke-service-agent
#
# Given this situation, this policy code allows users to choose whether to exclude GKE nodes or not.
excludes_gke_nodes := data.params.excludes_gke_nodes {
	data.params != null
	data.params.excludes_gke_nodes != null
} else := true

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	v4 := v4_addresses(instance.networkInterfaces, instance.name, instance.labels)
	v6 := v6_addresses(instance.networkInterfaces, instance.name, instance.labels)
	allowed := (count(v4) + count(v6)) == 0

	d := shisho.decision.googlecloud.compute.instance_public_ip({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_public_ip_payload({
			"public_ipv4_addresses": v4,
			"public_ipv6_addresses": v6,
		}),
	})
}

v4_addresses(networkInterfaces, instance_name, labels) := x {
	x := [interface.ipv4AccessConfig.natIp |
		not is_exception(instance_name, labels)

		count(networkInterfaces) > 0
		interface := networkInterfaces[_]

		interface.ipv4AccessConfig != null
		interface.ipv4AccessConfig.natIp != null
		interface.ipv4AccessConfig.natIp != ""
	]
} else := []

v6_addresses(networkInterfaces, instance_name, labels) := x {
	x := [sprintf("%s/%s", [interface.ipv6AccessConfig.externalIpv6, interface.ipv6AccessConfig.externalIpv6PrefixLength]) |
		not is_exception(instance_name, labels)

		count(networkInterfaces) > 0
		interface := networkInterfaces[_]

		interface.ipv6AccessConfig != null
		interface.ipv6AccessConfig.externalIpv6 != null
		interface.ipv6AccessConfig.externalIpv6 != ""
	]
} else := []

is_exception(instance_name, labels) {
	excludes_gke_nodes
	is_gke_node(instance_name, labels)
} else {
	not excludes_gke_nodes
} else = false

is_gke_node(instance_name, labels) {
	startswith(instance_name, "gke-")
	count([l.value |
		l := labels[_]
		l.value == "goog-gke-node"
	]) > 0
} else = false
