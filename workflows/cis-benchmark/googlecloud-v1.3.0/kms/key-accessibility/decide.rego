package policy.googlecloud.kms.key_accessibility

import data.shisho

forbidden_principals := [
	"allAuthenticatedUsers",
	"allUsers",
]

decisions[d] {
	project := input.googleCloud.projects[_]
	key_ring := project.kms.keyRings[_]
	key := key_ring.keys[_]

	fb := forbidden_bindings(key.iamPolicy.bindings)
	d := shisho.decision.googlecloud.kms.key_accessibility({
		"allowed": count(fb) == 0,
		"subject": key.metadata.id,
		"payload": shisho.decision.googlecloud.kms.key_accessibility_payload({"forbidden_bindings": fb}),
	})
}

forbidden_bindings(bindings) = x {
	x := {{"principal": member.id, "role": binding.role} |
		binding := bindings[_]

		member := binding.members[_]
		member.id == forbidden_principals[_]
	}
}
