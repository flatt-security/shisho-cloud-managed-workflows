package policy.aws.sns.kms_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	topic := account.sns.topics[_]

	d := shisho.decision.aws.sns.kms_encryption({
		"allowed": allow_if_excluded(topic.kmsMasterKeyId != "", topic),
		"subject": topic.metadata.id,
		"payload": shisho.decision.aws.sns.kms_encryption_payload({"kms_master_key_id": topic.kmsMasterKeyId}),
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
