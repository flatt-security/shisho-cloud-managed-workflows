package policy.aws.waf.classic_rule_condition

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	acl := account.wafClassic.webAcls[_]

	rules = [{"id": rule.id, "name": rule.name, "type": rule_type(rule.__typename), "predicate_data_ids": predicate_data_ids} |
		activated_rule := acl.activatedRules[_]
		rule := activated_rule.details
		predicate_data_ids := [predicate_data_id |
			predicate := rule.predicates[_]
			predicate_data_id := predicate.dataId
		]
	]
	count(rules) > 0

	d := shisho.decision.aws.waf.classic_rule_condition({
		"allowed": allow_if_excluded(rule_configured(rules), acl),
		"subject": acl.metadata.id,
		"payload": shisho.decision.aws.waf.classic_rule_condition_payload({"rules": rules}),
	})
}

rule_configured(rules) = false {
	rule := rules[_]
	count(rule.predicate_data_ids) == 0
} else = true

rule_type(type_name) = "REGULAR" {
	type_name == "AWSWAFClassicRule"
} else = "RATE_BASED" {
	type_name == "AWSWAFClassicRateBasedRule"
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
