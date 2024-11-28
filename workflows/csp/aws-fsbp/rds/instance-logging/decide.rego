package policy.aws.rds.instance_logging

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	d := shisho.decision.aws.rds.instance_logging({
		"allowed": allow_if_excluded(enabled_log(instance.engine, instance.enabledCloudwatchLogsExports), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_logging_payload({"log_types": instance.enabledCloudwatchLogsExports}),
	})
}

enabled_log(engine, log_types) {
	types := required_log_types(engine)
	sorted_types = sort(types)
	sorted_log_types = sort(log_types)
	sorted_types == sorted_log_types
} else = false

required_log_types(engine) := ["audit", "error", "general", "slowquery"] {
	engine in ["MYSQL", "MARIADB", "AURORA", "AURORA_MYSQL"]
} else := ["audit", "alert", "trace", "listener"] {
	startswith(engine, "ORACLE")
} else := ["postgresql", "upgrade"] {
	engine in ["POSTGRES", "AURORA_POSTGRESQL"]
} else := ["error", "agent"] {
	startswith(engine, "SQLSERVER")
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
