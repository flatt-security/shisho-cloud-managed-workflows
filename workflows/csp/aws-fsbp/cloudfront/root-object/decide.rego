package policy.aws.cloudfront.root_object

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := has_default_root_object(dist.config)
	d := shisho.decision.aws.cloudfront.default_root_object({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.default_root_object_payload({"default_root_object": default_root_object(dist.config)}),
	})
}

has_default_root_object(cfg) {
	default_root_object(cfg) != ""
} else := false

default_root_object(cfg) := cfg.defaultRootObject {
	cfg.defaultRootObject != null
	cfg.defaultRootObject != ""
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
