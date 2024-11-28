package policy.aws.networking.sg_ingress_rules

import data.shisho
import future.keywords.in

authorized_tcp_ports := data.params.authorized_tcp_ports {
	data.params != null
	data.params.authorized_tcp_ports != null
} else := [80, 443]

authorized_udp_ports := data.params.authorized_udp_ports {
	data.params != null
	data.params.authorized_udp_ports != null
} else := []

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]
	group := vpc.securityGroups[_]

	rules := ingress_rules(group.ipPermissionsIngress)
	d := shisho.decision.aws.networking.sg_ingress_rules({
		"allowed": allow_if_excluded(all_rules_allowed(rules), group),
		"subject": group.metadata.id,
		"payload": shisho.decision.aws.networking.sg_ingress_rules_payload({"ingress_rules": rules}),
	})
}

all_rules_allowed(rules) = false {
	rule := rules[_]
	rule.source_cidr == "0.0.0.0/0"
	rule.includes_irregular_ports
} else = true

ingress_rules(rules) = x {
	x := [{
		"source_cidr": source_cidr,
		"from_port": rule.fromPort,
		"to_port": rule.toPort,
		"includes_irregular_ports": includes_irregular_ports(rule.protocol, open_ports(rule)),
	} |
		rule := rules[_]
		source_cidr := rule.ipv4Ranges[_].cidrIpv4
	]
} else = []

includes_irregular_ports(protocol, ports) {
	protocol == "tcp"
	includes_irregular_tcp_ports(ports)
} else {
	protocol == "udp"
	includes_irregular_udp_ports(ports)
} else {
	protocol == "all"
	includes_irregular_tcp_ports(ports)
} else {
	protocol == "all"
	includes_irregular_udp_ports(ports)
} else = false

includes_irregular_tcp_ports(ports) {
	port := ports[_]
	not port in authorized_tcp_ports
} else = false

includes_irregular_udp_ports(ports) {
	port := ports[_]
	not port in authorized_udp_ports
} else = false

open_ports(rule) = numbers.range(1, 65535) {
	rule.fromPort == 0
	rule.toPort == 0
} else = numbers.range(rule.fromPort, rule.toPort)

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
