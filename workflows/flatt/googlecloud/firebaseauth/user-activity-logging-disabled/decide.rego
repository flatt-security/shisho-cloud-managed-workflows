package policy.googlecloud.firebaseauth.user_activity_logging_disabled

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# check if the user activity logging is disabled based on the project scope
	allowed_project_scope := project.firebaseAuthentication.settings.userActivityLoggingDisabled == false

	# list up the user activity logging configuration per tenant scope
	scopes := tenant_scopes(project.identityPlatform.tenants)

	d := shisho.decision.googlecloud.firebaseauth.user_activity_logging({
		"allowed": allowed(allowed_project_scope, scopes),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.firebaseauth.user_activity_logging_payload({
			"enabled": project.firebaseAuthentication.settings.userActivityLoggingDisabled == false,
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
	tenant_scope.enabled == false
} else := true

tenant_scopes(tenants) := x {
	x := [{
		"tenant_name": tenant.displayName,
		"enabled": is_request_logging_enabled(tenant.monitoring),
	} |
		tenant := tenants[_]
	]
} else := []

is_request_logging_enabled(monitoring) {
	monitoring != null
	monitoring.requestLogging != null
	monitoring.requestLogging.enabled == true
} else := false
