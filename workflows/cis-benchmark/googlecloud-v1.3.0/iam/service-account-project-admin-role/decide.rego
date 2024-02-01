package policy.googlecloud.iam.service_account_project_admin_role

import data.shisho

# the list of allowed service account emails using regex
allowed_service_account_email_regexes := data.params.allowed_service_account_email_regexes {
	data.params != null
	data.params.allowed_service_account_email_regexes != null
} else := []

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
		is_allowed_service_account(member.email) == false
	]
} else := []

is_suspicious_role(role) {
	contains(role, "Admin")
} else {
	contains(role, "admin")
} else {
	role == "roles/editor"
} else {
	role == "roles/owner"
} else = false

is_allowed_service_account(d) {
	regex.match(allowed_service_account_email_regexes[_], d)
} else := false
