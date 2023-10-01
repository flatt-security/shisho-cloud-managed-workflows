package policy.aws.cloudtrail.log_bucket_accessibility

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	trail := account.cloudTrail.trails[_]

	accessible := is_publicly_accessible(trail.s3Bucket)
	d := shisho.decision.aws.cloudtrail.log_bucket_accessibility({
		"allowed": allow_if_excluded(accessible == false, trail),
		"subject": trail.metadata.id,
		"payload": shisho.decision.aws.cloudtrail.log_bucket_accessibility_payload({
			"bucket_name": trail.s3Bucket.name,
			"acl_rules": [{
				"grantee_url": grant.grantee.displayName,
				"permission": grant.permission,
			} |
				grant := trail.s3Bucket.aclGrants[_]
			],
			"bucket_policy_document": trail.s3Bucket.policy.rawDocument,
		}),
	})
}

is_publicly_accessible(s3Bucket) {
	has_insecure_acl_grants(s3Bucket.aclGrants)
} else {
	has_insecure_bucket_policy(s3Bucket.policy.rawDocument)
} else = false

has_insecure_acl_grants(grants) {
	grant := grants[_]
	denied_uris := [
		"https://acs.amazonaws.com/groups/global/AllUsers",
		"https://acs.amazonaws.com/groups/global/AuthenticatedUsers",
	]
	denied_uris[_] == grant.grantee.uri
} else = false

has_insecure_bucket_policy(raw_document) {
	p := json.unmarshal(raw_document)

	statement := p.Statement[_]
	statement.Effect == "Allow"
	is_public_principal(statement.Principal)
} else = false

is_public_principal(principal) {
	principal == "*"
} else {
	principal.AWS == "*"
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
