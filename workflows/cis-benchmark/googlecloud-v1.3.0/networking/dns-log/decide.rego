package policy.googlecloud.networking.dns_log

import data.shisho

# For each VPC network
decisions[d] {
	project := input.googleCloud.projects[_]
	network := project.network.vpcNetworks[_]

	enabled := is_log_enabled(network)
	d := shisho.decision.googlecloud.networking.dns_log({
		"allowed": enabled,
		"subject": network.metadata.id,
		"payload": shisho.decision.googlecloud.networking.dns_log_payload({
			"dns_policy_attached": has_attached_policy(network),
			"log_enabled": enabled,
		}),
	})
}

# For a policy not attached to any network
decisions[d] {
	project := input.googleCloud.projects[_]
	policy := project.network.dnsPolicies[_]

	enabled := policy.enableLogging
	d := shisho.decision.googlecloud.networking.dns_log({
		"allowed": enabled,
		"subject": policy.metadata.id,
		"payload": shisho.decision.googlecloud.networking.dns_log_payload({
			"dns_policy_attached": false,
			"log_enabled": enabled,
		}),
	})
}

dns_policies := {n.url: {"enableLogging": policy.enableLogging} |
	project := input.googleCloud.projects[_]
	policy := project.network.dnsPolicies[_]
	n := policy.networks[_]
}

is_log_enabled(network) {
	p := dns_policies[network.selfLink]
	p.enableLogging
} else = false {
	true
}

has_attached_policy(network) {
	dns_policies[network.selfLink] != null
} else = false {
	true
}
