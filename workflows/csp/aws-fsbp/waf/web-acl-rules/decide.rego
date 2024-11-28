package policy.aws.waf.web_acl_rules

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	acl := account.waf.webAcls[_]

	rules = [rule.name |
		rule := acl.rules[_]
	]

	d := shisho.decision.aws.waf.web_acl_rules({
		"allowed": allow_if_excluded(count(rules) > 0, acl),
		"subject": acl.metadata.id,
		"payload": shisho.decision.aws.waf.web_acl_rules_payload({"rules": rules}),
	})
}

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
