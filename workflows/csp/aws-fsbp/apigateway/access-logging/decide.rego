package policy.aws.apigateway.access_logging

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	stages := stages_with_access_log_settings(api.stages)
	count(stages) > 0

	d := shisho.decision.aws.apigateway.access_logging({
		"allowed": allow_if_excluded(is_configured_access_log(stages), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.access_logging_payload({"stages": stages}),
	})
}

is_configured_access_log(stages) = false {
	stage := stages[_]
	stage.access_log_destination_arn == ""
} else = true

stages_with_access_log_settings(stages) := x {
	x := [{"name": stage.name, "access_log_destination_arn": destination_arn(stage.accessLogSettings)} |
		stage := stages[_]
	]
} else = []

destination_arn(access_log_settings) := arn {
	arn := access_log_settings.destinationArn
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
