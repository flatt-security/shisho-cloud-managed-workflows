package policy.aws.ecr.repository_lifecycle_policy_config

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	repo := account.ecr.repositories[_]

	rules := policy_rules(repo.lifecyclePolicy)

	d := shisho.decision.aws.ecr.repository_lifecycle_policy_config({
		"allowed": allow_if_excluded(
			count(rules) > 0,
			repo,
		),
		"subject": repo.metadata.id,
		"payload": shisho.decision.aws.ecr.repository_lifecycle_policy_config_payload({"lifecycle_policy_rules": rules}),
	})
}

policy_rules(lifecycle_policy) = x {
	x = [rule.description |
		policy := json.unmarshal(lifecycle_policy.policy.rawDocument)
		rule := policy.rules[_]
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
