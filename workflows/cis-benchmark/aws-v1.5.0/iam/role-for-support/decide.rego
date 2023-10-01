package policy.aws.iam.role_for_support

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	roles := roles_for_support(account.iam.policies)
	users := users_for_support(account.iam.policies)
	groups := groups_for_support(account.iam.policies)

	d := shisho.decision.aws.iam.role_for_support({
		"allowed": count(array.concat(array.concat(roles, users), groups)) > 0,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.role_for_support_payload({
			"attached_roles": roles,
			"attached_groups": groups,
			"attached_users": users,
		}),
	})
}

roles_for_support(policies) := x {
	x := [r.name |
		policy := policies[_]
		policy.name == "AWSSupportAccess"
		count(policy.entities.roles) > 0
		r := policy.entities.roles[_]
	]
}

users_for_support(policies) := x {
	x := [u.name |
		policy := policies[_]
		policy.name == "AWSSupportAccess"
		count(policy.entities.users) > 0
		u := policy.entities.users[_]
	]
}

groups_for_support(policies) := x {
	x := [g.name |
		policy := policies[_]
		policy.name == "AWSSupportAccess"
		count(policy.entities.groups) > 0
		g := policy.entities.groups[_]
	]
}
