package policy.aws.flatt.cognito.unauth_idp

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	idp := account.cognito.identityPools[_]

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1",
		"kind": "aws_cognito_unauthenticated_role",
		"subject": idp.metadata.id,
		"locator": "",
		"severity": shisho.decision.severity_critical,
		"allowed": allow_if_excluded(has_risky_scenario(idp) == false, idp),
		"payload": json.marshal({"roleArn": role_arn(idp)}),
	})
}

has_risky_scenario(idp) {
	idp.allowUnauthenticatedIdentities
	has_role(idp)
} else = false

has_role(idp) {
	role_arn(idp) != ""
} else = false

role_arn(idp) := x {
	x := idp.roleAssignment.perAuth.unauthenticatedRoleArn
	x != null
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
