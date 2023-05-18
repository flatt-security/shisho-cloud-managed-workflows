package policy.aws.networking.sg_ingress_v4

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]
	g := vpc.securityGroups[_]

	allowed := has_insecure_rule(g.ipPermissionsIngress) == false

	d := shisho.decision.aws.networking.sg_ingress_v4({
		"allowed": allowed,
		"subject": g.metadata.id,
		"payload": shisho.decision.aws.networking.sg_ingress_v4_payload({}),
	})
}

has_insecure_rule(rules) {
	rule := rules[_]
	range := rule.ipv4Ranges[_]
	range.cidrIpv4 == "0.0.0.0/0"

	any([
		allows(rule.fromPort, rule.toPort, 22),
		allows(rule.fromPort, rule.toPort, 3389),
	])
} else = false

allows(from, to, port) {
	from <= port
	port <= to
} else {
	from == 0
	to == 0
} else = false
