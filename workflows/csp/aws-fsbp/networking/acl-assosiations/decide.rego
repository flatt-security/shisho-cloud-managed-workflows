package policy.aws.networking.acl_assosiations

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]

	acls := acls_with_associations(vpc.acls)

	d := shisho.decision.aws.networking.acl_assosiations({
		"allowed": allow_if_excluded(is_no_associations(acls), vpc),
		"subject": vpc.metadata.id,
		"payload": shisho.decision.aws.networking.acl_assosiations_payload({"acls": acls}),
	})
}

is_no_associations(acls) = false {
	acl := acls[_]
	acl.number_of_associations == 0
} else = true

acls_with_associations(acls) = x {
	x := [{"id": acl.id, "number_of_associations": count(acl.associations)} |
		acl := acls[_]
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
