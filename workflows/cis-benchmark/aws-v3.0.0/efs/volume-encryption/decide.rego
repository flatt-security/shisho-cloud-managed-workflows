package policy.aws.efs.volume_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	filesystem := account.efs.fileSystems[_]

	encrypted := filesystem.encrypted
	d := shisho.decision.aws.efs.volume_encryption({
		"allowed": allow_if_excluded(encrypted, filesystem),
		"subject": filesystem.metadata.id,
		"payload": shisho.decision.aws.efs.volume_encryption_payload({"encrypted": encrypted}),
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
