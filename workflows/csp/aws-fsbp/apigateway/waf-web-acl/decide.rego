package policy.aws.apigateway.waf_web_acl

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	stages := stages_with_web_acl(api.stages)
	count(stages) > 0

	d := shisho.decision.aws.apigateway.waf_web_acl({
		"allowed": allow_if_excluded(is_used_web_acl(stages), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.waf_web_acl_payload({"stages": stages}),
	})
}

is_used_web_acl(stages) = false {
	stage := stages[_]
	stage.web_acl_arn == ""
} else = true

stages_with_web_acl(stages) := x {
	x := [{"name": stage.name, "web_acl_arn": stage.webAclArn} |
		stage := stages[_]
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
