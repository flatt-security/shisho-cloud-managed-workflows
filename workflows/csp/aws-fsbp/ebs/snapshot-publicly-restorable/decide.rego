package policy.aws.ebs.snapshot_publicly_restorable

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	s := account.ec2.snapshots[_]
	ss := snapshots_with_permissions([s])

	d := shisho.decision.aws.ebs.snapshot_publicly_restorable({
		"allowed": is_restorable(ss),
		"subject": s.metadata.id,
		"payload": shisho.decision.aws.ebs.snapshot_publicly_restorable_payload({"snapshots": ss}),
	})
}

snapshots_with_permissions(snapshots) = x {
	x := [{
		"id": snapshot.id,
		"volume_id": snapshot.volumeId,
		"create_volume_permissions": [{
			"group": permission.group,
			"user_id": permission.userId,
		} |
			permission := snapshot.attribute.createVolumePermissions[_]
		],
	} |
		snapshot := snapshots[_]
	]
}

is_restorable(snapshots) = false {
	snapshot := snapshots[_]
	permission := snapshot.create_volume_permissions[_]
	permission.group == "ALL"
	permission.user_id == ""
} else = true
