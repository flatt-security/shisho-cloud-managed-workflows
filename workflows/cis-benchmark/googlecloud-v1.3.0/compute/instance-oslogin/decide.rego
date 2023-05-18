package policy.googlecloud.compute.instance_oslogin

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	enabled := is_oslogin_enabled(instance.instanceMetadata)

	d := shisho.decision.googlecloud.compute.instance_oslogin({
		"allowed": enabled,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_oslogin_payload({"oslogin_enabled": enabled}),
	})
}

is_oslogin_enabled(metadata) {
	# the number of medata items shoud be greater than 0
	count(metadata.items) > 0

	# check if the metadata item with key "enable-oslogin" exists and value is "true"
	item := metadata.items[_]
	item.key == "enable-oslogin"
	lower(item.value) == "true"
} else = false {
	true
}
