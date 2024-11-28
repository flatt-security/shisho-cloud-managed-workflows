package policy.aws.lambda.runtime

import data.shisho
import future.keywords.in

supported_runtimes := [
	"DOTNET6", "GO1_X", "JAVA17", "JAVA11", "JAVA8", "JAVA8_AL2",
	"NODEJS18_X", "NODEJS16_X", "NODEJS14_X",
	"PYTHON3_12", "PYTHON3_11", "PYTHON3_10", "PYTHON3_9", "PYTHON3_8", "PYTHON3_7",
	"RUBY2_7",
]

decisions[d] {
	account := input.aws.accounts[_]
	function := account.lambda.functions[_]

	function.packageType != "IMAGE"

	d := shisho.decision.aws.lambda.runtime({
		"allowed": allow_if_excluded(is_allowed_runtime(function.runtime), function),
		"subject": function.metadata.id,
		"payload": shisho.decision.aws.lambda.runtime_payload({"runtime": function.runtime}),
	})
}

is_allowed_runtime(runtime) {
	runtime in supported_runtimes
} else = false

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
