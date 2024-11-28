package policy.aws.waf.classic_web_acl_logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	acl := account.wafClassic.webAcls[_]

	d := shisho.decision.aws.waf.classic_web_acl_logging({
		"allowed": allow_if_excluded(acl.loggingConfiguration != null, acl),
		"subject": acl.metadata.id,
		"payload": shisho.decision.aws.waf.classic_web_acl_logging_payload({"log_destinations": log_destinations(acl.loggingConfiguration)}),
	})
}

log_destinations(log_config) = log_config.logDestinationConfigurations {
	log_config != null
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
