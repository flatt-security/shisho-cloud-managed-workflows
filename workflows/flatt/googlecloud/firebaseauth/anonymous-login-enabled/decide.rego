package policy.googlecloud.firebaseauth.anonymous_login_enabled

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# check if the anonymous login is enabled based on the project scope
	allowed_project_scope := project.firebaseAuthentication.settings.anonymousLoginEnabled == false

	# list up the anonymous login availability per tenant scope
	scopes := tenant_scopes(project.identityPlatform.tenants)

	d := shisho.decision.googlecloud.firebaseauth.anonymous_login({
		"allowed": allowed(allowed_project_scope, scopes),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.firebaseauth.anonymous_login_payload({
			"enabled": project.firebaseAuthentication.settings.anonymousLoginEnabled,
			"tenant_scopes": scopes,
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
	tenant_scope.enabled == true
} else := true

tenant_scopes(tenants) := x {
	x := [{
		"tenant_name": tenant.displayName,
		"enabled": tenant.enableAnonymousUser,
	} |
		tenant := tenants[_]
	]
} else := []
