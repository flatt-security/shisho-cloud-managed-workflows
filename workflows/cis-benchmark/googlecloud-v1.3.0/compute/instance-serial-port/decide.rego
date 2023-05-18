package policy.googlecloud.compute.instance_serial_port

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	enabled := is_serial_port_enabled(instance.instanceMetadata)

	d := shisho.decision.googlecloud.compute.instance_serial_port({
		"allowed": enabled == false,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_serial_port_payload({"serial_port_enabled": enabled}),
	})
}

is_serial_port_enabled(metadata) {
	count(metadata.items) > 0

	item := metadata.items[_]
	item.key == "serial-port-enable"
	any([item.value == "1", lower(item.value) == "true"])
} else = false {
	true
}
