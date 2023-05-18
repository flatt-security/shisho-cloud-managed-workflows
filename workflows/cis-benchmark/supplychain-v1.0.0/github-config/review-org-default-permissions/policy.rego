package policy.github.config.review_org_default_permissions

import data.shisho

# default permission on organizations' repository
default_repository_permission_allowlist := [
	"none",
	"read",
]

is_allowed_default_repository_permission(elem) {
	default_repository_permission_allowlist[_] = elem
}

decisions[d] {
	org := input.github.organizations[_]
	allowed := is_allowed_default_repository_permission(org.defaultRepositoryPermission)

	d := shisho.decision.github.org_default_repository_permission({
		"allowed": allowed,
		"subject": org.metadata.id,
		"payload": shisho.decision.github.org_default_repository_permission_payload({"current": org.defaultRepositoryPermission}),
	})
}

# default permission on forking private repositories in organizations
is_forking_private_repos_allowed = false

decisions[d] {
	org := input.github.organizations[_]
	allowed := org.canMembersForkPrivateRepositories == is_forking_private_repos_allowed

	d := shisho.decision.github.org_members_permission_on_private_forking({
		"allowed": allowed,
		"subject": org.metadata.id,
		"payload": shisho.decision.github.org_members_permission_on_private_forking_payload({"allowed": org.canMembersForkPrivateRepositories}),
	})
}

# default permission on creating public repositories in organizations
is_creating_public_repos_allowed = false

decisions[d] {
	org := input.github.organizations[_]
	allowed := org.canMembersCreatePublicRepositories == is_creating_public_repos_allowed

	d := shisho.decision.github.org_members_permission_on_creating_public_repos({
		"allowed": allowed,
		"subject": org.metadata.id,
		"payload": shisho.decision.github.org_members_permission_on_creating_public_repos_payload({"allowed": org.canMembersCreatePublicRepositories}),
	})
}

# default permission on creating public pages in organizations
is_creating_public_pages_allowed = false

decisions[d] {
	org := input.github.organizations[_]
	allowed := org.canMembersCreatePublicPages == is_creating_public_pages_allowed

	d := shisho.decision.github.org_members_permission_on_creating_public_pages({
		"allowed": allowed,
		"subject": org.metadata.id,
		"payload": shisho.decision.github.org_members_permission_on_creating_public_pages_payload({"allowed": org.canMembersCreatePublicPages}),
	})
}
