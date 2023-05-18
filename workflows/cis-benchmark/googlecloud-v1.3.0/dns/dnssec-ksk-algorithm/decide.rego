package policy.googlecloud.dns.dnssec_ksk_algorithm

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	zone := project.network.dnsManagedZones[_]
	specs := zone.dnssecConfiguration.defaultKeySpecs

	allowed := has_algorithm_rsasha1(specs) == false

	d := shisho.decision.googlecloud.dns.dnssec_ksk_algorithm({
		"allowed": allowed,
		"subject": zone.metadata.id,
		"payload": shisho.decision.googlecloud.dns.dnssec_ksk_algorithm_payload({"algorithms": algorithms(specs)}),
	})
}

has_algorithm_rsasha1(defaultKeySpecs) {
	spec := defaultKeySpecs[_]

	spec.algorithm == "RSASHA1"
} else = false {
	true
}

algorithms(defaultKeySpecs) := x {
	x := [algorithm |
		spec := defaultKeySpecs[_]
		algorithm := spec.algorithm
	]
}
