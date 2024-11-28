package policy.aws.kms.key_deletion

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	key := account.kms.keys[_]

	key.keyManager == "CUSTOMER"

	d := shisho.decision.aws.kms.key_deletion({
		"allowed": allow_if_excluded(key.keyState != "PENDING_DELETION", key),
		"subject": key.metadata.id,
		"payload": shisho.decision.aws.kms.key_deletion_payload({
			"state": key.keyState,
			"deleted_at": deleted_at(key.daletedAt),
		}),
	})
}

deleted_at(daleted_at) = daleted_at {
	daleted_at != null
} else = ""

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
