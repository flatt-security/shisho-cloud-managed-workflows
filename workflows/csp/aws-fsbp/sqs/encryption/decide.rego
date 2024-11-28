package policy.aws.sqs.encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	queue := account.sqs.queues[_]

	id := kms_master_key_id(queue.serverSideEncryption.kmsConfiguration)

	d := shisho.decision.aws.sqs.encryption({
		"allowed": allow_if_excluded(id != "", queue),
		"subject": queue.metadata.id,
		"payload": shisho.decision.aws.sqs.encryption_payload({"kms_master_key_id": id}),
	})
}

kms_master_key_id(kms_configuration) := id {
	id := kms_configuration.masterKeyId
} else := ""

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
