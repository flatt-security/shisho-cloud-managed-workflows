package policy.aws.waf.classic_web_acl_rules

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	acl := account.wafClassic.webAcls[_]

	rules = associated_rules(acl.activatedRules)

	d := shisho.decision.aws.waf.classic_web_acl_rules({
		"allowed": allow_if_excluded(count(rules) > 0, acl),
		"subject": acl.metadata.id,
		"payload": shisho.decision.aws.waf.classic_web_acl_rules_payload({"rules": rules}),
	})
}

associated_rules(activated_rules) = x {
	x = [{"id": rule.id, "name": rule.name, "type": rule_type(rule.__typename)} |
		activated_rule := activated_rules[_]
		rule := activated_rule.details
	]
} else = []

rule_type(type_name) = "REGULAR" {
	type_name == "AWSWAFClassicRule"
} else = "RATE_BASED" {
	type_name == "AWSWAFClassicRateBasedRule"
} else = "RULE_GROUP" {
	type_name == "AWSWAFClassicRuleGroup"
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
