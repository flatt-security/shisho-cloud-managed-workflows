package policy.googlecloud.logging.api_audit

import data.shisho
import future.keywords

test_whether_audit_logging_is_enabled_for_projects if {
	# check if the audit logging is enabled for projects
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "googlecloud-project|514893257777"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": [],
					},
				],
			}]},
		},
		{
			"metadata": {"id": "googlecloud-project|514893258888"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": [],
					},
				],
			}]},
		},
	]}}

	# check if the audit logging is disabled for projects
	# because some types are missed
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "googlecloud-project|514893257777"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": [],
					},
				],
			}]},
		},
		{
			"metadata": {"id": "googlecloud-project|514893258888"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
				],
			}]},
		},
	]}}

	# check if the audit logging is disabled for projects
	# because `service` is not `allServices`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "googlecloud-project|514893257777"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "logging.googleapis.com",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": [],
					},
				],
			}]},
		},
		{
			"metadata": {"id": "googlecloud-project|514893258888"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "logging.googleapis.com",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": [],
					},
				],
			}]},
		},
	]}}

	# check if the audit logging is disabled for projects
	# because exemptedMembers are not empty
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "googlecloud-project|514893257777"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": ["testmember@example.com"],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": [],
					},
				],
			}]},
		},
		{
			"metadata": {"id": "googlecloud-project|514893258888"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [
					{
						"type": "ADMIN_READ",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_WRITE",
						"exemptedMembers": [],
					},
					{
						"type": "DATA_READ",
						"exemptedMembers": ["testmember@example.com"],
					},
				],
			}]},
		},
	]}}

	# check if the audit logging is disabled for projects
	# because `auditConfigurations` is empty
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {"id": "googlecloud-project|514893257777"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [],
			}]},
		},
		{
			"metadata": {"id": "googlecloud-project|514893258888"},
			"iamPolicy": {"auditConfigurations": [{
				"service": "allServices",
				"configurations": [],
			}]},
		},
	]}}
}
