package policy.aws.rds.instance_copy_tags_to_snapshots

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]
	allowed := instance.copyTagsToSnapshot

	d := shisho.decision.aws.rds.instance_copy_tags_to_snapshots({
		"allowed": allow_if_excluded(allowed, instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_copy_tags_to_snapshots_payload({"enabled": allowed}),
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
