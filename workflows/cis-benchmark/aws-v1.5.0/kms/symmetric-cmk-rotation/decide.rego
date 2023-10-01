package policy.aws.kms.symmetric_cmk_rotation

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	key := account.kms.keys[_]

	key.keyManager == "CUSTOMER"
	key.keySpec == "SYMMETRIC_DEFAULT"
	allowed := key.keyRotationEnabled == true

	d := shisho.decision.aws.kms.symmetric_cmk_rotation({
		"allowed": allow_if_excluded(allowed, key),
		"subject": key.metadata.id,
		"payload": shisho.decision.aws.kms.symmetric_cmk_rotation_payload({"enabled": allowed}),
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
