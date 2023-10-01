package policy.googlecloud.support.access_approval

import data.shisho
import future.keywords

test_whether_access_approval_is_enabled_for_projects if {
	# check if the access approval is enabled for projects
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"accessApproval": {"settings": {"name": "test-approval-settings-1"}},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"accessApproval": {"settings": {"name": "test-approval-settings-2"}},
		},
	]}}

	# check if the access approval is enabled for projects
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"accessApproval": {"settings": null},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-2",
			},
			"accessApproval": {"settings": null},
		},
	]}}
}
