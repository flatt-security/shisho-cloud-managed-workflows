package policy.googlecloud.networking.fw_rule_iap

import data.shisho
import future.keywords.every

# The policy confirms that each VPC allows traffic to the following ports only from the IAP proxy and Google Health Check.
# - 80/tcp
# - 443/tcp
#
# If you want to restrict the access to other ports as well, you can add them to the `restriction_targets` list.
# When all ports should be protected, TBD!!!
restriction_targets := [
	{
		"protocol": "tcp",
		"port": 80,
	},
	{
		"protocol": "tcp",
		"port": 443,
	},
]

google_source_ranges := [
	"35.235.240.0/20", # IAP Proxy Addresses
	"130.211.0.0/22", # Google Health Check
	"35.191.0.0/16", # Google Health Check
]

decisions[d] {
	project := input.googleCloud.projects[_]
	network := project.network.vpcNetworks[_]

	# List up all ingress rules from the firewall rules that may affect security of restriction targets.
	related_rules := related_ingress_rules(network.firewallRules)

	# The VPC is allowed if and only if the rules allow traffic only from Google ranges.
	allowed := allow_traffic_only_from_google_ranges(related_rules)

	d := shisho.decision.googlecloud.networking.fw_rule_iap({
		"allowed": allowed,
		"subject": network.metadata.id,
		"payload": shisho.decision.googlecloud.networking.fw_rule_iap_payload({"ingress_rules": related_rules}),
	})
}

# Returns the ingress firewall rules that may affect security of apps served under `restriction_targets`.
related_ingress_rules(firewall_rules) = x {
	x := [{"name": rule.name, "source_ranges": rule.sourceRanges, "allow_rules": related_allow_rules} |
		# On each ingress rule ...
		rule := firewall_rules[_]
		rule.direction == "INGRESS"

		# confirm the rule may affect `restriction target`.
		# Note: if `related_allow_rules` is empty, the `rule` does not affect security of `restriction_targets`.
		related_allow_rules := [{"ip_protocol": allow_rule.ipProtocol, "port_ranges": allow_rule.ports} |
			allow_rule := rule.allowed[_]
			may_affect_restriction_target(allow_rule)
		]
		count(related_allow_rules) > 0
	]
} else = []

# An allow rule in a firewall rule affects security of restriction targets if and only if ....
may_affect_restriction_target(allow_rule) {
	# For a restriction target ...
	restriction_target := restriction_targets[_]

	# the rule uses the target protocol ...
	restriction_target.protocol == allow_rule.ipProtocol

	# and the rule has a port range that includes the target port.	
	include_ports(allow_rule.ports, restriction_target.port)
} else := false

# Note: a port range can be empty, and the rule allows all ports in that case.
# Reference: https://cloud.google.com/compute/docs/reference/rest/v1/firewalls and Shisho Cloud datasource GraphQL schema
include_ports(ports, p) {
	range := ports[_]

	range.from <= p
	p <= range.to
} else {
	count(ports) == 0
} else = false

# Confirm all of the given rules have source ranges within Google ranges.
#
# Note: If no *allowing* firewall rule, the traffic will be blocked by *implied deny ingress rule*.
# That's why this function returns true even if `rules` is empty.
# https://cloud.google.com/firewall/docs/firewalls#default_firewall_rules
allow_traffic_only_from_google_ranges(rules) {
	every rule in rules {
		every range in rule.source_ranges {
			net.cidr_contains(google_source_ranges[_], range)
		}
	}
} else = false
