package policy.googlecloud.asset.management

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	allowed := includes_cloudasset_api(project.services)

	d := shisho.decision.googlecloud.asset.management({
		"allowed": allowed,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.asset.management_payload({"enabled": allowed}),
	})
}

includes_cloudasset_api(services) {
	service := services[_]
	service.name == "cloudasset.googleapis.com"
} else = false
