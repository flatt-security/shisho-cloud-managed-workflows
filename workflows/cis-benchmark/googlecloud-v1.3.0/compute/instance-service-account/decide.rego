package policy.googlecloud.compute.instance_service_account

import data.shisho

excludes_gke_nodes := data.params.excludes_gke_nodes {
	data.params != null
	data.params.excludes_gke_nodes != null
} else := true

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	allowed := uses_unpermitted_default_account(
		project.number,
		instance.name,
		instance.serviceAccount.email,
		instance.labels,
	) == false

	d := shisho.decision.googlecloud.compute.instance_service_account({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_service_account_payload({
			"uses_default_account": instance.serviceAccount.email == default_service_account(project.number),
			"service_account_email": instance.serviceAccount.email,
		}),
	})
}

# CIS Google Cloud Platform Foundation Benchmark v1.3.0 describes that the GKE nodes should be excluded.
# 
# However, there is less logical reason to have exception, and Google Cloud also recommends to set a minimum role:
# https://cloud.google.com/kubernetes-engine/docs/how-to/service-accounts?hl=ja#default-gke-service-agent
# 
# Given this situation, this policy code allows users to choose whether to exclude GKE nodes or not.
uses_unpermitted_default_account(project_number, instance_name, email, labels) {
	email == default_service_account(project_number)

	excludes_gke_nodes
	not is_gke_node(instance_name, labels)
} else {
	email == default_service_account(project_number)

	not excludes_gke_nodes
} else = false

# a Google Compute Engine instance created by GKE should be excluded.
is_gke_node(instance_name, labels) {
	startswith(instance_name, "gke-")
	count(labels) > 0
	count([l.value |
		l := labels[_]
		l.value == "goog-gke-node"
	]) > 0
} else = false

# return an email of the default service account 
# the format of default service account is '[PROJECT_NUMBER]-compute@developer.gserviceaccount.com'
default_service_account(project_number) := x {
	x := sprintf("%d-compute@developer.gserviceaccount.com", [project_number])
}
