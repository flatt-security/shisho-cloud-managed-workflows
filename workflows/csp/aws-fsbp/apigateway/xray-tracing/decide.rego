package policy.aws.apigateway.xray_tracing

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	stages := stages_with_tracing(api.stages)
	d := shisho.decision.aws.apigateway.xray_tracing({
		"allowed": allow_if_excluded(enabled_tracing(stages), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.xray_tracing_payload({"stages": stages}),
	})
}

enabled_tracing(stages) = false {
	stage := stages[_]
	stage.tracing_enabled == false
} else = true

stages_with_tracing(stages) := x {
	x := [{"name": stage.name, "tracing_enabled": stage.tracingEnabled} |
		stage := stages[_]
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
