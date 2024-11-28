package policy.googlecloud.firebaseauth.accounts_can_be_deleted_by_end_user

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# check if the end user cannot delete their account based on the project scope
	allowed_project_scope := project.firebaseAuthentication.settings.accountsCanBeDeletedByEndUser == false

	# list up the account deletion permission per tenant scope
	scopes := tenant_scopes(project.identityPlatform.tenants)

	d := shisho.decision.googlecloud.firebaseauth.account_deletion({
		"allowed": allowed(allowed_project_scope, scopes),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.firebaseauth.account_deletion_payload({
			"can_be_deleted": allowed_project_scope == false,
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
	tenant_scope.can_be_deleted == true
} else := true

tenant_scopes(tenants) := x {
	x := [{
		"tenant_name": tenant.displayName,
		"can_be_deleted": is_user_deletion_disabled(tenant.client) == false,
	} |
		tenant := tenants[_]
	]
} else := []

is_user_deletion_disabled(client) {
	client != null
	client.permissions != null
	client.permissions.disabledUserDeletion == true
} else := false
