package policy.aws.rds.cluster_administrator_username

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.rds.clusters[_]

	excluded_engines(cluster.engine) == false

	d := shisho.decision.aws.rds.cluster_administrator_username({
		"allowed": allow_if_excluded(use_admin(cluster.masterUsername), cluster),
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.rds.cluster_administrator_username_payload({"admin_username": cluster.masterUsername}),
	})
}

use_admin(username) = false {
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
