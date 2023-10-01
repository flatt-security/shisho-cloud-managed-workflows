package policy.googlecloud.compute.instance_confidential_computing

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	status := confidential_computing(instance)

	d := shisho.decision.googlecloud.compute.instance_confidential_computing({
		"allowed": status != shisho.decision.googlecloud.compute.CONFIDENTIAL_COMPUTING_STATUS_DISABLED,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_confidential_computing_payload({
			"confidential_computing_status": status,
			"machine_type": instance.machineType,
		}),
	})
}

confidential_computing(instance) := shisho.decision.googlecloud.compute.CONFIDENTIAL_COMPUTING_STATUS_ENABLED {
	is_supported_instance_type(instance.machineType)
	instance.confidentialInstanceConfiguration.enableConfidentialCompute == true
} else = shisho.decision.googlecloud.compute.CONFIDENTIAL_COMPUTING_STATUS_UNSUPPORTED {
	not is_supported_instance_type(instance.machineType)
} else = shisho.decision.googlecloud.compute.CONFIDENTIAL_COMPUTING_STATUS_DISABLED

# Confidential Computing is currently only supported on N2D/C2D machines
# https://cloud.google.com/confidential-computing/confidential-vm/docs/os-and-machine-type#machine-type
is_supported_instance_type(machine_type) {
	startswith(machine_type, "n2d-")
} else {
	startswith(machine_type, "c2d-")
} else = false
