package policy.aws.s3.bucket_public_read_access

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	config := bucket.publicAccessBlockConfiguration

	grants := acl_grants(bucket.aclGrants)

	document := json.unmarshal(bucket.policy.rawDocument)
	statements := statements_with_public_read_access_state(document)

	d := shisho.decision.aws.s3.bucket_public_read_access({
		"allowed": allow_if_excluded(is_read_access_blocked(config, grants, statements), bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_public_read_access_payload({
			"acl_grants": grants,
			"policy_allowed_statements": statements,
			"block_public_acls": config.blockPublicAcls,
			"block_public_policy": config.blockPublicPolicy,
		}),
	})
}

is_read_access_blocked(config, grants, statements) {
	insecure_acl_grants(config, grants) == false
	insecure_policy(config, statements) == false
} else = false

insecure_acl_grants(config, grants) {
	config.blockPublicAcls == false

	grant := grants[_]
	grant.uri in ["http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
	grant.permission in ["FULL_CONTROL", "READ", "READ_ACP"]
} else = false

acl_grants(grants) := x {
	x := [{
		"display_name": grant.grantee.displayName,
		"uri": grant.grantee.uri, "permission": grant.permission,
	} |
		grant := grants[_]
	]
} else := []

insecure_policy(config, statements) {
	config.blockPublicPolicy == false

	statement := statements[_]
	statement.public_read_access_denied == false
} else = false

statements_with_public_read_access_state(document) := x {
	x := [{
		"sid": sid(statement),
		"public_read_access_denied": public_read_access_denied(statement),
	} |
		statement := document.Statement[_]
		statement.Effect == "Allow"
	]
} else = []

public_read_access_denied(statement) = false {
	action := statement.Action
	principal := statement.Principal

	# The action includes s3 read-ish
	denied_actions := ["*", "*:*", "s3:*"]
	[
		denied_actions[_] == action,
		startswith(lower(action), "s3:get"),
		startswith(lower(action), "s3:list"),
	][_] == true

	# The principal is the wildcard
	[
		principal == "*",
		principal_aws(principal) == "*",
		principal_aws(principal) == ["*"],
	][_] == true

	# No suspicious Condition
	not has_ip_limitation(statement)
} else = true

has_ip_limitation(statement) {
	statement.Condition.StringEquals["aws:SourceIp"] != null
} else {
	statement.Condition.StringNotEquals["aws:SourceIp"] != null
} else {
	statement.Condition.StringEqualsIgnoreCase["aws:SourceIp"] != null
} else {
	statement.Condition.StringNotEqualsIgnoreCase["aws:SourceIp"] != null
} else {
	statement.Condition.StringLike["aws:SourceIp"] != null
} else {
	statement.Condition.StringNotLike["aws:SourceIp"] != null
} else = false

principal_aws(principal) := p {
	p := principal.AWS
} else = ""

sid(statement) := sid {
	sid := statement.Sid
} else = ""

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
