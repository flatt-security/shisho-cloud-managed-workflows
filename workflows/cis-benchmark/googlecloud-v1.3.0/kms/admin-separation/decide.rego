package policy.googlecloud.kms.admin_separation

import data.shisho

# the roles should not be owned by principals having a KMS admin role
user_roles := [
	"roles/cloudkms.cryptoKeyDecrypter",
	"roles/cloudkms.cryptoKeyEncrypter",
	"roles/cloudkms.cryptoKeyEncrypterDecrypter",
]

decisions[d] {
	project := input.googleCloud.projects[_]

	a := admins(project.iamPolicy.bindings)
	ub := user_bindings(project.iamPolicy.bindings)

	d := shisho.decision.googlecloud.kms.admin_separation({
		"allowed": count(a & {u.principal | u := ub[_]}) == 0,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.kms.admin_separation_payload({
			"admin_principals": a,
			"users": ub,
		}),
	})
}

admins(bindings) := x {
	x := {member.id |
		binding := bindings[_]
		binding.role == "roles/cloudkms.admin"

		member := binding.members[_]
		member.deleted == false
	}
} else = []

user_bindings(bindings) := x {
	x := {{
		"principal": member.id,
		"role": binding.role,
	} |
		binding := bindings[_]
		binding.role == user_roles[_]

		member := binding.members[_]
		member.deleted == false
	}
} else = []
