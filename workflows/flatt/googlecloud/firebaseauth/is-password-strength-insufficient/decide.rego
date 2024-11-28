package policy.googlecloud.firebaseauth.is_password_strength_insufficient

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# check if the password policy has an insufficient minimum length based on the project scope
	allowed_project_scope := has_insufficient_minimum_length(project.firebaseAuthentication.settings.passwordPolicy)

	# list up the password policy per tenant scope
	scopes := tenant_scopes(project.identityPlatform.tenants)

	d := shisho.decision.googlecloud.firebaseauth.password_strength({
		"allowed": allowed(allowed_project_scope, scopes),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.firebaseauth.password_strength_payload({
			"min_length": min_length(project.firebaseAuthentication.settings.passwordPolicy),
			"tenant_scopes": scopes,
		}),
	})
}

has_insufficient_minimum_length(password_policy) := false {
	# check if the minimum length of the password policy is less than 8
	min_length(password_policy) < 8
} else := true

min_length(password_policy) := v.customStrengthOptions.minimumLength {
	count(password_policy.passwordPolicyVersions) > 0
	v := password_policy.passwordPolicyVersions[0]
}

allowed(project_scope, tenant_scopes) {
	project_scope == true
	allowed_tenant_scopes(tenant_scopes) == true
} else {
	project_scope == true
	count(tenant_scopes) == 0
} else := false

allowed_tenant_scopes(tenant_scopes) := false {
	tenant_scope := tenant_scopes[_]

	# check if the minimum length of the password policy is less than 8
	tenant_scope.min_length < 8
} else := true

tenant_scopes(tenants) := x {
	x := [{
		"tenant_name": tenant.displayName,
		"min_length": min_length_of_tenant_scope(tenant.passwordPolicyConfiguration),
	} |
		tenant := tenants[_]
	]
} else := []

# get the minimum length of the password policy for a tenant scope
# the default minimum length is 6 if the policy is not set
min_length_of_tenant_scope(configuration) := version.customStrengthOptions.minimumPasswordLength {
	configuration != null
	count(configuration.versions) == 1
	version := configuration.versions[0]
	version.customStrengthOptions != null
} else := 6
