package policy.googlecloud.storage.bucket_accessibility

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	bucket := project.cloudStorage.buckets[_]

	policy_bindings := public_policy_bindings(bucket.iamPolicy.bindings)
	acl_bindings := public_acl_rules(bucket.acl)

	d := shisho.decision.googlecloud.storage.bucket_accessibility({
		"allowed": (count(policy_bindings) + count(acl_bindings)) == 0,
		"subject": bucket.metadata.id,
		"payload": shisho.decision.googlecloud.storage.bucket_accessibility_payload({
			"public_policy_bindings": policy_bindings,
			"public_acl_rules": acl_bindings,
		}),
	})
}

is_public_principal(p) {
	p == "allAuthenticatedUsers"
} else {
	p == "allUsers"
} else = false {
	true
}

is_public_entity(p) := is_public_principal(p)

public_acl_rules(acl) := x {
	x := [{
		"role": a.role,
		"entity": a.entity,
	} |
		a := acl[_]
		is_public_entity(a.entity)
	]
} else := [] {
	true
}

public_policy_bindings(bindings) := x {
	x := [{
		"role": binding.role,
		"principal": member.id,
	} |
		binding := bindings[_]
		member := binding.members[_]
		is_public_principal(member.id)
	]
} else := [] {
	true
}
