package policy.googlecloud.firebaseauth.password_policy_disabled

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# check if the password policy is disabled based on the project scope
	allowed_project_scope := project.firebaseAuthentication.settings.passwordPolicyDisabled == false

	# list up the password policy per tenant scope
	scopes := tenant_scopes(project.identityPlatform.tenants)

	d := shisho.decision.googlecloud.firebaseauth.password_policy({
		"allowed": allowed(allowed_project_scope, scopes),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.firebaseauth.password_policy_payload({
			"enabled_password_policy": project.firebaseAuthentication.settings.passwordPolicyDisabled == false,
			"tenant_scopes": tenant_scopes(project.identityPlatform.tenants),
		}),
	})
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
	not tenant_scope.enabled_password_policy
} else := false {
	tenant_scope := tenant_scopes[_]
	not tenant_scope.enforced_password_policy
} else := true

tenant_scopes(tenants) := x {
	x := [{
		"tenant_name": tenant.displayName,
		"enabled_password_policy": tenant.passwordPolicyConfiguration != null,
		"enforced_password_policy": is_enforced_password_policy(tenant.passwordPolicyConfiguration),
	} |
		tenant := tenants[_]
	]
} else := []

is_enforced_password_policy(password_policy_configuration) := false {
	password_policy_configuration == null
} else := false {
	password_policy_configuration != null
	password_policy_configuration.enforcementState != "ENFORCE"
} else := true
