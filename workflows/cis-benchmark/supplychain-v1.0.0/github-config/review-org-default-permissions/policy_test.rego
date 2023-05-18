package policy.github.config.review_org_default_permissions

import data.shisho
import future.keywords

test_whether_default_repository_permission_is_properly_configured if {
	# check whether all repositoreis have `none` or `read` permissions as default
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_org_default_repository_permission"
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"github": {"organizations": [
		{
			"metadata": {"id": "github|62992581|organization"},
			"defaultRepositoryPermission": "none",
		},
		{
			"metadata": {"id": "github|79221271|organization"},
			"defaultRepositoryPermission": "none",
		},
		{
			"metadata": {"id": "github|83053041|organization"},
			"defaultRepositoryPermission": "read",
		},
	]}}

	# check whether some repositoreis have `write` permissions as default
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_org_default_repository_permission"
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"github": {"organizations": [
		{
			"metadata": {"id": "github|62992581|organization"},
			"defaultRepositoryPermission": "write", # = accept to provide a `write` permission as default. `write` permissions are carefully provided depending on the members 
		},
		{
			"metadata": {"id": "github|79221271|organization"},
			"defaultRepositoryPermission": "none",
		},
		{
			"metadata": {"id": "github|83053041|organization"},
			"defaultRepositoryPermission": "read",
		},
	]}}
}

test_whether_permissions_of_forking_private_repositories_are_properly_configured if {
	# check whether members can fork private repositories for organizations
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_org_members_permission_on_private_forking"
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"github": {"organizations": [
		{
			"metadata": {"id": "github|62992581|organization"},
			"canMembersForkPrivateRepositories": false,
		},
		{
			"metadata": {"id": "github|79221271|organization"},
			"canMembersForkPrivateRepositories": false,
		},
		{
			"metadata": {"id": "github|83053041|organization"},
			"canMembersForkPrivateRepositories": false,
		},
	]}}

	# check whether members cannot fork private repositories for organizations
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_org_members_permission_on_private_forking"
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"github": {"organizations": [
		{
			"metadata": {"id": "github|62992581|organization"},
			"canMembersForkPrivateRepositories": true, # = forking private repositories in an organization is allowed
		},
		{
			"metadata": {"id": "github|79221271|organization"},
			"canMembersForkPrivateRepositories": false,
		},
		{
			"metadata": {"id": "github|83053041|organization"},
			"canMembersForkPrivateRepositories": false,
		},
	]}}
}

test_whether_permissions_of_creating_public_pages_are_properly_configured if {
	# check whether members can create public pages for organizations
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_org_members_permission_on_creating_public_pages"
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"github": {"organizations": [
		{
			"metadata": {"id": "github|62992581|organization"},
			"canMembersCreatePublicPages": false,
		},
		{
			"metadata": {"id": "github|79221271|organization"},
			"canMembersCreatePublicPages": false,
		},
		{
			"metadata": {"id": "github|83053041|organization"},
			"canMembersCreatePublicPages": false,
		},
	]}}

	# check whether members cannot create public pages for organizations
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_org_members_permission_on_creating_public_pages"
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"github": {"organizations": [
		{
			"metadata": {"id": "github|62992581|organization"},
			"canMembersCreatePublicPages": true, # = creating puclic pages is allowed  
		},
		{
			"metadata": {"id": "github|79221271|organization"},
			"canMembersCreatePublicPages": false,
		},
		{
			"metadata": {"id": "github|83053041|organization"},
			"canMembersCreatePublicPages": false,
		},
	]}}
}
