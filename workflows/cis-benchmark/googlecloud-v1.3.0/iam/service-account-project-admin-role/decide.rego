package policy.googlecloud.iam.service_account_project_admin_role

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	bindings := permissive_project_bindings(project.iamPolicy.bindings)
	d := shisho.decision.googlecloud.iam.service_account_project_admin_role({
		"allowed": count(bindings) == 0,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.iam.service_account_project_admin_role_payload({"suspicious_bindings": bindings}),
	})
}

permissive_project_bindings(bindings) := x {
	x := [{
		"role": binding.role,
		"service_account_email": member.email,
	} |
		binding := bindings[_]
		is_suspicious_role(binding.role)

		member := binding.members[_]
		member.__typename == "GoogleCloudIAMPrincipalServiceAccount"
		member.email != null
	]
} else := [] {
	true
}

is_suspicious_role(role) {
	contains(role, "Admin")
} else {
	contains(role, "admin")
} else {
	role == "roles/editor"
} else {
	role == "roles/owner"
} else = false {
	true
}
