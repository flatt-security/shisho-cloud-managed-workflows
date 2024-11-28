package policy.aws.waf.classic_rule_group_attached_rules

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	acl := account.wafClassic.webAcls[_]

	rule_groups = [{"id": rule_group.id, "name": rule_group.name, "rule_ids": rule_ids} |
		activated_rule := acl.activatedRules[_]
		rule_group := activated_rule.details
		rule_ids := [rule.details.id |
			rule := rule_group.rules[_]
		]
	]
	count(rule_groups) > 0

	d := shisho.decision.aws.waf.classic_rule_group_attached_rules({
		"allowed": allow_if_excluded(rules_attached(rule_groups), acl),
		"subject": acl.metadata.id,
		"payload": shisho.decision.aws.waf.classic_rule_group_attached_rules_payload({"rule_groups": rule_groups}),
	})
}

rules_attached(rule_groups) = false {
	group := rule_groups[_]
	count(group.rule_ids) == 0
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
