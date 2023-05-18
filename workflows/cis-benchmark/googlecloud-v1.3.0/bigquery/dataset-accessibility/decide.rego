package policy.googlecloud.bigquery.dataset_accessibility

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	dataset := project.bigQuery.datasets[_]

	authenticated := all_authenticated_users_roles(dataset.access)
	all := all_users_roles(dataset.access)

	d := shisho.decision.googlecloud.bigquery.dataset_accessibility({
		"allowed": is_allowed(authenticated, all),
		"subject": dataset.metadata.id,
		"payload": shisho.decision.googlecloud.bigquery.dataset_accessibility_payload({
			"all_authenticated_users_roles": authenticated,
			"all_users_roles": all,
		}),
	})
}

is_allowed(authenticated, all) {
	count(authenticated) == 0
	count(all) == 0
} else = false {
	true
}

all_authenticated_users_roles(access) = x {
	x := [a.role |
		a := access[_]
		a.__typename == "GoogleCloudBigQueryDatasetAccessSpecialGroup"
		a.name == "allAuthenticatedUsers"
	]
} else = [] {
	true
}

all_users_roles(access) = x {
	x := [a.role |
		a := access[_]
		a.__typename == "GoogleCloudBigQueryDatasetAccessIamMember"
		a.memberType == "allUsers"
	]
} else = [] {
	true
}
