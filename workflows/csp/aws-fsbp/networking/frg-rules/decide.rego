package policy.aws.networking.frg_rules

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	group := account.network.firewallRuleGroups[_]

	rules := number_of_rules(group.rules)

	d := shisho.decision.aws.networking.frg_rules({
		"allowed": allow_if_excluded(rules > 0, group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.networking.frg_rules_payload({"number_of_rules": rules}),
	})
}

number_of_rules(rules) = count(rules.source.rulesAndCustomActions.rules) {
	rules.source.rulesAndCustomActions != null
} else = 0

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
