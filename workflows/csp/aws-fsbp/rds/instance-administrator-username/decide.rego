package policy.aws.rds.instance_administrator_username

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	excluded_engines(instance.engine) == false

	d := shisho.decision.aws.rds.instance_administrator_username({
		"allowed": allow_if_excluded(admin_user(instance.masterUsername), instance),
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_administrator_username_payload({"engine": instance.engine, "admin_username": instance.masterUsername}),
	})
}

admin_user(username) = false {
	username in ["admin", "postgres"]
} else = true

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
