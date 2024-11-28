package policy.googlecloud.firebaseauth.email_listing_protection_disabled

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# check if the email listing protection is disabled based on the project scope
	allowed_project_scope := project.firebaseAuthentication.settings.emailListingProtectionDisabled == false

	# list up the email listing protection per tenant scope
	scopes := tenant_scopes(project.identityPlatform.tenants)

	d := shisho.decision.googlecloud.firebaseauth.email_listing_protection({
		"allowed": allowed(allowed_project_scope, scopes),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.firebaseauth.email_listing_protection_payload({
			"enabled_email_listing_protection": project.firebaseAuthentication.settings.emailListingProtectionDisabled == false,
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
	tenant_scope.enabled_improved_email_privacy == false
} else := true

tenant_scopes(tenants) := x {
	x := [{
		"tenant_name": tenant.displayName,
		"enabled_improved_email_privacy": is_improved_email_privacy_enabled(tenant.emailPrivacyConfiguration),
	} |
		tenant := tenants[_]
	]
} else := []

is_improved_email_privacy_enabled(configuration) {
	configuration != null
	configuration.enableImprovedEmailPrivacy == true
} else := false
