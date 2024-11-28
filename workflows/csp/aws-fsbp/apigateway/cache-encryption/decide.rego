package policy.aws.apigateway.cache_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	stages := stages_with_cache_status(api.stages)
	count(stages) > 0

	d := shisho.decision.aws.apigateway.cache_encryption({
		"allowed": allow_if_excluded(enabled_cache_encryption(stages), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.cache_encryption_payload({"stages": stages}),
	})
}

enabled_cache_encryption(stages) = false {
	stage := stages[_]
	stage.caching_enabled == true
	stage.cache_encryption_enabled == false
} else = true

stages_with_cache_status(stages) := x {
	x := [{"name": stage.name, "caching_enabled": caching, "cache_encryption_enabled": cache_encryption} |
		stage := stages[_]
		setting_values := [setting.value |
			setting := stage.methodSettings[_]
			setting.key == "*/*"
		]
		caching := setting_values[0].cachingEnabled
		cache_encryption := setting_values[0].cacheDataEncrypted
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
