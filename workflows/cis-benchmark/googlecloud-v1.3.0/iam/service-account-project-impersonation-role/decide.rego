package policy.googlecloud.iam.service_account_project_impersonation_role

import data.shisho

# the list of allowed service account emails using regex
allowed_service_account_email_regexes := data.params.allowed_service_account_email_regexes {
	data.params != null
	data.params.allowed_service_account_email_regexes != null
} else := []

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
		is_allowed_service_account(member) == false
	]
} else := []

can_impersonate_or_attach(role) {
	role == "roles/iam.serviceAccountUser"
} else {
	role == "roles/iam.serviceAccountTokenCreator"
} else = false

is_allowed_service_account(d) {
	d.__typename == "GoogleCloudIAMPrincipalServiceAccount"
	d.email != null
	regex.match(allowed_service_account_email_regexes[_], d.email)
} else := false
