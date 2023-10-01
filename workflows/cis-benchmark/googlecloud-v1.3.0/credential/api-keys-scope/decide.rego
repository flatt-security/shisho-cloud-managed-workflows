package policy.googlecloud.credential.api_keys_scope

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	key := project.credentials.apiKeys[_]
	key.deletedAt == null

	d := shisho.decision.googlecloud.credential.api_keys_scope({
		"allowed": has_restriction_target(key),
		"subject": key.metadata.id,
		"payload": shisho.decision.googlecloud.credential.api_keys_scope_payload({"targets": restriction_targets(key)}),
	})
}

has_restriction_target(key) {
	count(restriction_targets(key)) > 0
} else := false

restriction_targets(key) := key.restriction.apiTargets {
	key.restriction != null
} else := []
