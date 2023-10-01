package policy.googlecloud.compute.instance_oslogin

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	enabled := is_oslogin_enabled(project.computeEngine.projectMetadata, instance.instanceMetadata)
	d := shisho.decision.googlecloud.compute.instance_oslogin({
		"allowed": enabled,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.instance_oslogin_payload({"oslogin_enabled": enabled}),
	})
}

# The instance-level metadata overrides the project-level metadata, and the default is disabled.
#
# Project-level metadata requires compute.projects.get permission on the project, which is not included in the default setup.
# If you want to use project-level metadata for supressing the metadata, you need to add the permission to the service account.
is_oslogin_enabled(projectMetadata, instanceMetadata) := x {
	count(instanceMetadata.items) > 0

	item := instanceMetadata.items[_]
	item.key == "enable-oslogin"
	x := any([item.value == "1", lower(item.value) == "true"])
} else := x {
	count(projectMetadata.items) > 0

	item := projectMetadata.items[_]
	item.key == "enable-oslogin"
	x := any([item.value == "1", lower(item.value) == "true"])
} else = false
