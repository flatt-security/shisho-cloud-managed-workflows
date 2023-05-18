package policy.googlecloud.dns.dnssec

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	zone := project.network.dnsManagedZones[_]

	allowed := zone.dnssecConfiguration.state == "ON"

	d := shisho.decision.googlecloud.dns.dnssec({
		"allowed": allowed,
		"subject": zone.metadata.id,
		"payload": shisho.decision.googlecloud.dns.dnssec_payload({"dnssec_enabled": allowed}),
	})
}
