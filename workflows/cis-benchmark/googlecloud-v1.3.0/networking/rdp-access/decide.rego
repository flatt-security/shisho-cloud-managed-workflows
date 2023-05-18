package policy.googlecloud.networking.rdp_access

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	network := project.network.vpcNetworks[_]

	surfaces := rdp_access_surfaces(network.firewallRules)
	d := shisho.decision.googlecloud.networking.rdp_access({
		"allowed": count(surfaces) == 0,
		"subject": network.metadata.id,
		"payload": shisho.decision.googlecloud.networking.rdp_access_payload({"exposed_surfaces": surfaces}),
	})
}

rdp_access_surfaces(firewallRules) := x {
	x := [{"network_self_link": rule.network} |
		rule := firewallRules[_]
		rule.direction == "INGRESS"
		allows_public_traffic(rule.sourceRanges)

		item := rule.allowed[_]
		allows_rdp_protocol(item.ipProtocol)
		allows_rdp_default_port(item.ports)
	]
} else := [] {
	true
}

# review the given set of ranges includes is "0.0.0.0/0"
allows_public_traffic(source_ranges) {
	range := source_ranges[_]
	range == "0.0.0.0/0"
} else = false {
	true
}

# NOTE: a firewall rule without any port ranges specified allows all ports
allows_rdp_default_port(ports) {
	port := ports[_]
	range_includes(port, 3389)
} else {
	count(ports) == 0
} else = false {
	true
}

range_includes(r, p) {
	r.from == p
	r.to == p
} else {
	r.from <= p
	p <= r.to
} else {
	false
}

# if the IP protocol is "all" or "tcp", return true
allows_rdp_protocol(protocol) {
	protocol == "all"
} else {
	protocol == "tcp"
} else = false {
	true
}
