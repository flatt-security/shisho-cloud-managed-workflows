package policy.aws.secretsmanager.auto_rotation

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	secret := account.secretsManager.secrets[_]

	d := shisho.decision.aws.secretsmanager.auto_rotation({
		"allowed": allow_if_excluded(secret.rotationEnabled, secret),
		"subject": secret.metadata.id,
		"payload": shisho.decision.aws.secretsmanager.auto_rotation_payload({"enabled": secret.rotationEnabled}),
	})
}

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
