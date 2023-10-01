package policy.googlecloud.support.access_approval

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	allowed := project.accessApproval.settings != null

	d := shisho.decision.googlecloud.support.access_approval({
		"allowed": allowed,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.support.access_approval_payload({"enabled": allowed}),
	})
}
