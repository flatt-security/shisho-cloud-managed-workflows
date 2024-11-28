package policy.aws.efs.access_point_root_directory

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	filesystem := account.efs.fileSystems[_]

	count(filesystem.accessPoints) > 0
	access_points := [{"id": point.id, "path": point.rootDirectory.path} |
		point := filesystem.accessPoints[_]
		point.rootDirectory.path
	]

	d := shisho.decision.aws.efs.access_point_root_directory({
		"allowed": allow_if_excluded(root_directory(access_points) == false, filesystem),
		"subject": filesystem.metadata.id,
		"payload": shisho.decision.aws.efs.access_point_root_directory_payload({"access_points": access_points}),
	})
}

root_directory(access_points) {
	point := access_points[_]
	point.path == "/"
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
