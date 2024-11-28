package policy.aws.apigateway.logging

import data.shisho
import future.keywords.in

denied_levels := ["", "OFF"]

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	stages := array.concat(
		v2_stages_with_logging_level(api.__typename, api.stages),
		stages_with_logging_level(api.__typename, api.stages),
	)
	count(stages) > 0

	d := shisho.decision.aws.apigateway.logging({
		"allowed": allow_if_excluded(allowed(stages), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.logging_payload({"stages": stages}),
	})
}

allowed(stages) = false {
	stage := stages[_]
	stage.logging_level in denied_levels
} else = true

v2_stages_with_logging_level(type_name, stages) := x {
	type_name in ["AWSAPIGatewayHTTPAPI", "AWSAPIGatewayWebSocketAPI"]

	x := [{"name": stage.name, "logging_level": stage.defaultRouteSettings.loggingLevel} |
		stage := stages[_]
	]
} else = []

stages_with_logging_level(type_name, stages) := x {
	type_name == "AWSAPIGatewayRestAPI"
	x := [{"name": stage.name, "logging_level": log_level(stage)} |
		stage := stages[_]
	]
} else = []

log_level(stage) = logging_level {
	values := [setting.value |
		setting := stage.methodSettings[_]
		setting.key == "*/*"
	]
	logging_level := values[0].loggingLevel
} else = "OFF"

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
