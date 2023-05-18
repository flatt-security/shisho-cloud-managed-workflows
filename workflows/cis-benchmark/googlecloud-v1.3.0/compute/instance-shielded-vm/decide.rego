package policy.googlecloud.compute.instance_shielded_vm

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	d := shisho.decision.googlecloud.compute.instance_shielded_vm({
		"allowed": is_allowed(instance.shieldedInstanceConfiguration),
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_shielded_vm_payload({
			"integrity_monitoring_enabled": integrity_monitoring_enabled(instance.shieldedInstanceConfiguration),
			"secure_boot_enabled": secure_boot_enabled(instance.shieldedInstanceConfiguration),
			"vtpm_enabled": vtpm_enabled(instance.shieldedInstanceConfiguration),
		}),
	})
}

is_allowed(cfg) {
	integrity_monitoring_enabled(cfg)
	vtpm_enabled(cfg)
} else = false

integrity_monitoring_enabled(cfg) {
	cfg != null
	cfg.enableIntegrityMonitoring
} else = false

secure_boot_enabled(cfg) {
	cfg != null
	cfg.enableSecureBoot
} else = false

vtpm_enabled(cfg) {
	cfg != null
	cfg.enableVtpm
} else = false
