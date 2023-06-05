package policy.aws.cloudfront.root_object

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := has_default_root_object(dist.config)
	d := shisho.decision.aws.cloudfront.default_root_object({
		"allowed": allowed,
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
