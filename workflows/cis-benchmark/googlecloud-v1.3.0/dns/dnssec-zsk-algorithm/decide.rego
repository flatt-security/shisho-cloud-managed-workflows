package policy.googlecloud.dns.dnssec_zsk_algorithm

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	zone := project.network.dnsManagedZones[_]
	specs := zone.dnssecConfiguration.defaultKeySpecs

	allowed := has_algorithm_rsasha1_and_zone_key(specs) == false

	d := shisho.decision.googlecloud.dns.dnssec_zsk_algorithm({
		"allowed": allowed,
		"subject": zone.metadata.id,
		"payload": shisho.decision.googlecloud.dns.dnssec_zsk_algorithm_payload({"algorithms": algorithms(specs)}),
	})
}

has_algorithm_rsasha1_and_zone_key(defaultKeySpecs) {
	spec := defaultKeySpecs[_]

	spec.algorithm == "RSASHA1"
	spec.type == "ZONE_SIGNING"
} else = false

algorithms(defaultKeySpecs) := x {
	x := [algorithm |
		spec := defaultKeySpecs[_]
		algorithm := spec.algorithm
	]
}
