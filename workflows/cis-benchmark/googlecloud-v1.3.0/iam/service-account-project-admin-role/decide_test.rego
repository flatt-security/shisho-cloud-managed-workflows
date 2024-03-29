package policy.googlecloud.iam.service_account_project_admin_role

import data.shisho
import future.keywords

test_permissive_project_iam_policy_failss if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"metadata": {"id": "googlecloud-project|5148937777"},
			"iamPolicy": {"bindings": [
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "5148937777@cloudbuild.gserviceaccount.com"}],
					"role": "roles/stackdriver.accounts.viewer",
				},
				{
					"members": ["serviceAccount:service-5148937777@gcp-sa-cloudbuild.iam.gserviceaccount.com"],
					"role": "roles/viewer",
				},
			]},
		},
		{
			"id": "test-project-3",
			"metadata": {"id": "googlecloud-project|5148939999"},
			"iamPolicy": {"bindings": []},
		},
		{
			"id": "test-project-4",
			"metadata": {"id": "googlecloud-project|5148930000"},
			"iamPolicy": {"bindings": [{
				"members": [],
				"role": "roles/editor",
			}]},
		},
	]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"metadata": {"id": "googlecloud-project|5148937777"},
			"iamPolicy": {"bindings": [
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "5148937777@cloudbuild.gserviceaccount.com"}],
					"role": "roles/iam.serviceAccountUser",
				},
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "service-5148937777@gcp-sa-cloudbuild.iam.gserviceaccount.com"}],
					"role": "roles/iam.serviceAccountAdmin",
				},
			]},
		},
		{
			"id": "test-project-2",
			"metadata": {"id": "googlecloud-project|5148938888"},
			"iamPolicy": {"bindings": [
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "5148938888@test-project-2.iam.gserviceaccount.com"}],
					"role": "roles/editor",
				},
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "service-5148938888@test-project-2.iam.gserviceaccount.com"}],
					"role": "roles/cloudsql.client",
				},
			]},
		},
		{
			"id": "test-project-2",
			"metadata": {"id": "googlecloud-project|5148938888"},
			"iamPolicy": {"bindings": [
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "5148938888@test-3.iam.gserviceaccount.com"}],
					"role": "roles/editor",
				},
				{
					"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "service-5148938888@test-3.iam.gserviceaccount.com"}],
					"role": "roles/cloudsql.client",
				},
			]},
		},
	]}}
}

test_service_account_project_admin_role_with_allowed_service_account if {
	test_input := {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"metadata": {"id": "googlecloud-project|5148937777"},
			"iamPolicy": {"bindings": [{
				"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "app@test-project-1.iam.gserviceaccount.com"}],
				"role": "roles/owner",
			}]},
		},
		{
			"id": "test-project-2",
			"metadata": {"id": "googlecloud-project|5148938888"},
			"iamPolicy": {"bindings": [{
				"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "admin@example-organization.iam.gserviceaccount.com"}],
				"role": "roles/owner",
			}]},
		},
		{
			"id": "test-project-3",
			"metadata": {"id": "googlecloud-project|5148939999"},
			"iamPolicy": {"bindings": [{
				"members": [{"__typename": "GoogleCloudIAMPrincipalServiceAccount", "email": "owner@example-organization.iam.gserviceaccount.com"}],
				"role": "roles/owner",
			}]},
		},
	]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as test_input

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as test_input
		with data.params.allowed_service_account_email_regexes as {"admin@example-organization\\.iam\\.gserviceaccount\\.com", ".*@example-organization\\.iam\\.gserviceaccount\\.com"}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 0 with input as test_input
		with data.params.allowed_service_account_email_regexes as {"*"}
}
