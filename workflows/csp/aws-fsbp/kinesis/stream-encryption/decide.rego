package policy.aws.kinesis.encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	stream := account.kinesis.streams[_]

	d := shisho.decision.aws.kinesis.stream_encryption({
		"allowed": allow_if_excluded(stream.encryptionType == "KMS", stream),
		"subject": stream.metadata.id,
		"payload": shisho.decision.aws.kinesis.stream_encryption_payload({"encryption_type": stream.encryptionType}),
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
