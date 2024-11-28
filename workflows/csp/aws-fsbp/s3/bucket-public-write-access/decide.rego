package policy.aws.s3.bucket_public_write_access

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]
	config := bucket.publicAccessBlockConfiguration

	grants := acl_grants(bucket.aclGrants)

	document := json.unmarshal(bucket.policy.rawDocument)
	statements := statements_with_public_write_access_state(document)

	d := shisho.decision.aws.s3.bucket_public_write_access({
		"allowed": allow_if_excluded(allowed(config, grants, statements), bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_public_write_access_payload({
			"acl_grants": grants,
			"policy_allowed_statements": statements,
			"block_public_acls": config.blockPublicAcls,
			"block_public_policy": config.blockPublicPolicy,
		}),
	})
}

allowed(config, grants, statements) {
	insecure_acl_grants(config, grants) == false
	insecure_policy(config, statements) == false
} else = false

insecure_acl_grants(config, grants) {
	config.blockPublicAcls == false

	grant := grants[_]
	grant.uri in ["http://acs.amazonaws.com/groups/global/AllUsers", "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"]
	grant.permission in ["FULL_CONTROL", "WRITE", "WRITE_ACP"]
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
	statement.public_write_access_denied == false
} else = false

statements_with_public_write_access_state(document) := x {
	x := [{"sid": statement.Sid, "public_write_access_denied": public_write_access_denied(statement.Action, statement.Principal)} |
		statement := document.Statement[_]
		statement.Effect == "Allow"
	]
} else = []

public_write_access_denied(action, principal) = false {
	denied_actions := ["*", "*:*", "s3:*"]
	[
		denied_actions[_] == action,
		startswith(lower(action), "s3:put"),
		startswith(lower(action), "s3:delete"),
		startswith(lower(action), "s3:create"),
		startswith(lower(action), "s3:update"),
		startswith(lower(action), "s3:replicate"),
		startswith(lower(action), "s3:restore"),
	][_] == true

	[
		principal == "*",
		principal_aws(principal) == "*",
		principal_aws(principal) == ["*"],
	][_] == true
} else = true

principal_aws(principal) := p {
	p := principal.AWS
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
