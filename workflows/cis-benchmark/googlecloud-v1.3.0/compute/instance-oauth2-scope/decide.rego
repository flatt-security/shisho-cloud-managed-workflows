package policy.googlecloud.compute.instance_oauth2_scope

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	allowed := uses_unpermitted_scope(
		project.number,
		instance.name,
		instance.serviceAccount.email,
		instance.labels,
		instance.serviceAccount.scopes,
	) == false

	d := shisho.decision.googlecloud.compute.instance_oauth2_scope({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_oauth2_scope_payload({
			"service_account_email": instance.serviceAccount.email,
			"assigned_scopes": instance.serviceAccount.scopes,
		}),
	})
}

uses_unpermitted_scope(
	# Google Cloud project number that the instance belongs to
	project_number,
	# A name of the instance
	instance_name,
	# An email of the service account attached to the instance
	sa_email,
	# Labels attached to the instance
	labels,
	# OAuth2 scopes attached to the instance
	scopes,
) {
	sa_email == default_service_account(project_number)
	contains_cloud_platform_scope(scopes)

	# Exception: GKE-managed instances will have the cloud-platform scope.
	not is_gke_node(instance_name, labels)
} else = false {
	true
}

# a Google Compute Engine instance created by GKE should be excluded.
is_gke_node(instance_name, labels) {
	startswith(instance_name, "gke-")
	contains_gke_labels(labels)
} else = false {
	true
}

contains_gke_labels(labels) {
	count([l.value |
		l := labels[_]
		l.value == "goog-gke-node"
	]) > 0
} else = false {
	true
}

# return an email of the default service account 
# the format of default service account is '[PROJECT_NUMBER]-compute@developer.gserviceaccount.com'
default_service_account(project_number) = x {
	x := sprintf("%d-compute@developer.gserviceaccount.com", [project_number])
}

# check if scopes contain "https://www.googleapis.com/auth/cloud-platform"
contains_cloud_platform_scope(scopes) {
	scope := scopes[_]
	scope == "https://www.googleapis.com/auth/cloud-platform"
} else = false {
	true
}
