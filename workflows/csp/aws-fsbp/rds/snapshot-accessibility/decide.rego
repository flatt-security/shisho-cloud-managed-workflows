package policy.aws.rds.snapshot_accessibility

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.rds.clusters[_]

	count(cluster.snapshots) > 0
	snapshots := [{
		"id": snapshot.id,
		"publicly_restorable": public_accessibility(snapshot.attributes),
	} |
		snapshot := cluster.snapshots[_]
	]

	d := shisho.decision.aws.rds.snapshot_accessibility({
		"allowed": allow_if_excluded(is_publicly_restorable(snapshots), cluster),
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.rds.snapshot_accessibility_payload({"engine": cluster.engine, "snapshots": snapshots}),
	})
}

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	count(instance.snapshots) > 0
	snapshots := [{
		"id": snapshot.id,
		"publicly_restorable": public_accessibility(snapshot.attributes),
	} |
		snapshot := instance.snapshots[_]
	]

	d := shisho.decision.aws.rds.snapshot_accessibility({
		"allowed": allow_if_excluded(is_publicly_restorable(snapshots), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.snapshot_accessibility_payload({"engine": instance.engine, "snapshots": snapshots}),
	})
}

is_publicly_restorable(snapshots) = false {
	snapshot := snapshots[_]
	snapshot.publicly_restorable == true
} else = true

public_accessibility(attributes) {
	attribute := attributes[_]
	attribute.values[_] == "all"
} else = false

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
