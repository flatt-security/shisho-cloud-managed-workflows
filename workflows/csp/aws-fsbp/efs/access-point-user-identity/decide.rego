package policy.aws.efs.access_point_user_identity

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	filesystem := account.efs.fileSystems[_]

	count(filesystem.accessPoints) > 0
	access_points_user_ids := [{"id": point.id, "user_id_enforced": point.posixUser != null} |
		point := filesystem.accessPoints[_]
	]

	d := shisho.decision.aws.efs.access_point_user_identity({
		"allowed": allow_if_excluded(allowed(access_points_user_ids), filesystem),
		"subject": filesystem.metadata.id,
		"payload": shisho.decision.aws.efs.access_point_user_identity_payload({"access_points": access_points_user_ids}),
	})
}

allowed(access_points_user_ids) = false {
	point := access_points_user_ids[_]
	point.user_id_enforced == false
} else = true

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
