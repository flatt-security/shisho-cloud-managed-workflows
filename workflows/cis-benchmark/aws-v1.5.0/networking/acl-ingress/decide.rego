package policy.aws.networking.acl_ingress

import data.shisho

ports_to_deny = [
	22,
	3389,
]

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]

	nacls := insecure_nacls(vpc.acls)
	allowed := count(nacls) == 0

	d := shisho.decision.aws.networking.acl_ingress({
		"allowed": allow_if_excluded(allowed, vpc),
		"subject": vpc.metadata.id,
		"payload": shisho.decision.aws.networking.acl_ingress_payload({"insecure_acls": nacls}),
	})
}

insecure_nacls(nacls) := x {
	x := [{"id": nacl.id} |
		nacl := nacls[_]
		has_insecure_entry(nacl)
	]
} else := []

has_insecure_entry(nacl) {
	p := ports_to_deny[_]
	e := nacl.entries[_]
	e.type == "INGRESS"
	e.cidrBlock == "0.0.0.0/0"
	e.ruleAction == "ALLOW"
	port_range_includes(e.portRange, p)
} else {
	p := ports_to_deny[_]
	e := nacl.entries[_]
	e.ipv6CidrBlock == "::/0"
	e.type == "INGRESS"
	e.ruleAction == "ALLOW"
	port_range_includes(e.portRange, p)
} else = false

port_range_includes(r, port) {
	r.from == 0
	r.to == 0
} else {
	r.from <= port
	port <= r.to
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
