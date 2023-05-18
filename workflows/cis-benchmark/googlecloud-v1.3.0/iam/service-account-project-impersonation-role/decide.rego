package policy.googlecloud.iam.service_account_project_impersonation_role

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	principals := permissive_principals(project.iamPolicy.bindings)
	allowed := count(principals) == 0

	d := shisho.decision.googlecloud.iam.service_account_project_impersonation_role({
		"allowed": allowed,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.iam.service_account_project_impersonation_role_payload({"permissive_principals": principals}),
	})
}

permissive_principals(bindings) := x {
	x := [member.id |
		binding := bindings[_]
		can_impersonate_or_attach(binding.role)

		member := binding.members[_]
	]
} else := []

can_impersonate_or_attach(role) {
	role == "roles/iam.serviceAccountUser"
} else {
	role == "roles/iam.serviceAccountTokenCreator"
} else = false
