package policy.aws.iam.user_group_permission_assignment

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	user = account.iam.users[_]

	policies := attached_policy_names(user.policies)

	d := shisho.decision.aws.iam.user_group_permission_assignment({
		"allowed": count(policies) == 0,
		"subject": user.metadata.id,
		"payload": shisho.decision.aws.iam.user_group_permission_assignment_payload({"attached_policy_names": policies}),
	})
}

attached_policy_names(policies) := x {
	x := [policy.name |
		policy := policies[_]
	]
}
