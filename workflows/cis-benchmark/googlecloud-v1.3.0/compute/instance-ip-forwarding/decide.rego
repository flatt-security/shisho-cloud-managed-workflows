package policy.googlecloud.compute.instance_ip_forwarding

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	d := shisho.decision.googlecloud.compute.instance_ip_forwarding({
		"allowed": instance.canIpForward == false,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_ip_forwarding_payload({"forwarding_enabled": instance.canIpForward}),
	})
}
