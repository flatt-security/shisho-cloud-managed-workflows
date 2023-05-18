package policy.googlecloud.compute.instance_project_wide_key_management

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	blocked := has_item_to_block_keys(instance.instanceMetadata.items)
	project_wide_key_available := has_ssh_keys(instance.instanceMetadata.items)

	d := shisho.decision.googlecloud.compute.instance_project_wide_key_management({
		"allowed": blocked,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_project_wide_key_management_payload({
			"blocked": blocked,
			"project_wide_key_available": project_wide_key_available,
		}),
		"severity": severity(instance.instanceMetadata.items),
	})
}

# return the configuration of "block-project-ssh-keys" in metadata items
has_item_to_block_keys(metadata_items) {
	i := metadata_items[_]
	i.key == "block-project-ssh-keys"
	lower(i.value) == "true"
} else = false {
	true
}

severity(metadata_items) := shisho.decision.severity_medium {
	has_ssh_keys(metadata_items)
} else := null {
	# NOTE: null means to use the default severity
	true
}

has_ssh_keys(metadata_items) {
	i := metadata_items[_]
	i.key == "ssh-keys"
	i.value != ""
} else = false {
	true
}
