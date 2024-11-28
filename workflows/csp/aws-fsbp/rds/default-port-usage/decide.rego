package policy.aws.rds.default_port_usage

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	excluded_engines(instance.engine) == false

	d := shisho.decision.aws.rds.default_port_usage({
		"allowed": allow_if_excluded(used_default_port(instance.engine, instance.port), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.default_port_usage_payload({"engine": instance.engine, "port": instance.port}),
	})
}

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.rds.clusters[_]

	excluded_engines(cluster.engine) == false

	d := shisho.decision.aws.rds.default_port_usage({
		"allowed": used_default_port(cluster.engine, cluster.port),
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.rds.default_port_usage_payload({"engine": cluster.engine, "port": cluster.port}),
	})
}

used_default_port(engine, port) = false {
	port == engine_default_port(engine)
} else = true

engine_default_port(engine) := 3306 {
	engine in ["AURORA", "AURORA_MYSQL", "MYSQL", "MARIADB"]
} else := 5432 {
	engine in ["AURORA_POSTGRESQL", "POSTGRES"]
} else := 1521 {
	startswith(engine, "ORACLE")
} else := 1433 {
	startswith(engine, "SQLSERVER")
} else := 0

excluded_engines(engine) {
	engine in ["DOCDB", "NEPTUNE"]
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
