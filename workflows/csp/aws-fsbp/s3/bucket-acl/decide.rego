package policy.aws.s3.bucket_acl

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	controls := ownership_controls(bucket.ownershipControls)

	d := shisho.decision.aws.s3.bucket_acl({
		"allowed": allow_if_excluded(allowed_acl(controls, bucket.aclGrants), bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_acl_payload({
			"bucket_acl_used": count(bucket.aclGrants) > 0,
			"ownership_controls": controls,
		}),
	})
}

allowed_acl(controls, acl_grants) {
	[
		enforced_controls(controls),
		count(acl_grants) == 0,
	][_] == true
} else = false

enforced_controls(controls) {
	controls[0] == "BUCKET_OWNER_ENFORCED"
} else = false

ownership_controls(controls) := x {
	x := [rule.objectOwnership |
		controls != null
		rule := controls.rules[_]
	]
} else = []

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
