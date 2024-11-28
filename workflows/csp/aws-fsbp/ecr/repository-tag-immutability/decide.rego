package policy.aws.ecr.repository_tag_immutability

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	repo := account.ecr.repositories[_]

	enabled := repo.imageTagMutability == "IMMUTABLE"

	d := shisho.decision.aws.ecr.repository_tag_immutability({
		"allowed": allow_if_excluded(enabled, repo),
		"subject": repo.metadata.id,
		"payload": shisho.decision.aws.ecr.repository_tag_immutability_payload({"tag_immutability_enabled": enabled}),
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
