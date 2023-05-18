package policy.googlecloud.iam.service_account_key

import data.shisho
import future.keywords

test_whether_user_managed_keys_of_service_accounts_do_not_exist if {
	# check if the the user-managed keys of service accounts does not exist
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 5 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"iam": {"serviceAccounts": [
				{
					"metadata": {"id": "googlecloud-iam-sa|5148937777|11487792595745627777"},
					"keys": [
						{
							"name": "projects/test-project-1/serviceAccounts/test-1@test-project-1.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
							"origin": "GOOGLE_PROVIDED",
							"type": "SYSTEM_MANAGED",
						},
						{
							"name": "projects/test-project-1/serviceAccounts/test-2@test-project-1.iam.gserviceaccount.com/keys/57bef4df2fa132db4b11409a43d2155bf09424c1",
							"origin": "GOOGLE_PROVIDED",
							"type": "SYSTEM_MANAGED",
						},
					],
				},
				{
					"metadata": {"id": "googlecloud-iam-sa|5148937777|114877925957456208888"},
					"keys": [{
						"name": "projects/test-project-1/serviceAccounts/test-3@test-project-1.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
						"origin": "GOOGLE_PROVIDED",
						"type": "SYSTEM_MANAGED",
					}],
				},
			]},
		},
		{
			"id": "test-project-2",
			"iam": {"serviceAccounts": [
				{
					"metadata": {"id": "googlecloud-project|5148938888|114877925957456208889"},
					"keys": [{
						"name": "projects/test-project-2/serviceAccounts/test-2@test-project-2.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
						"origin": "GOOGLE_PROVIDED",
						"type": "SYSTEM_MANAGED",
					}],
				},
				{
					"metadata": {"id": "googlecloud-project|5148938888|114877925957456209999"},
					"keys": [{
						"name": "projects/test-project-2/serviceAccounts/test-2@test-project-2.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
						"origin": "GOOGLE_PROVIDED",
						"type": "SYSTEM_MANAGED",
					}],
				},
			]},
		},
		{
			"id": "test-project-3",
			"iam": {"serviceAccounts": [{
				"metadata": {"id": "googlecloud-iam-sa|5148937777|11487792595745612345"},
				"keys": [],
			}]},
		},
	]}}

	# check if the the user-managed keys of service accounts does not exist
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"iam": {"serviceAccounts": [
				{
					"metadata": {"id": "googlecloud-iam-sa|5148937777|11487792595745627777"},
					"keys": [
						{
							"name": "projects/test-project-1/serviceAccounts/test-1@test-project-1.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
							"origin": "GOOGLE_PROVIDED",
							"type": "USER_MANAGED",
						},
						{
							"name": "projects/test-project-1/serviceAccounts/test-2@test-project-1.iam.gserviceaccount.com/keys/57bef4df2fa132db4b11409a43d2155bf09424c1",
							"origin": "GOOGLE_PROVIDED",
							"type": "USER_MANAGED",
						},
					],
				},
				{
					"metadata": {"id": "googlecloud-iam-sa|5148937777|114877925957456208888"},
					"keys": [{
						"name": "projects/test-project-1/serviceAccounts/test-3@test-project-1.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
						"origin": "GOOGLE_PROVIDED",
						"type": "USER_MANAGED",
					}],
				},
			]},
		},
		{
			"id": "test-project-2",
			"iam": {"serviceAccounts": [
				{
					"metadata": {"id": "googlecloud-project|5148938888|114877925957456208888"},
					"keys": [{
						"name": "projects/test-project-2/serviceAccounts/test-2@test-project-2.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
						"origin": "GOOGLE_PROVIDED",
						"type": "USER_MANAGED",
					}],
				},
				{
					"metadata": {"id": "googlecloud-project|5148938888|114877925957456209999"},
					"keys": [{
						"name": "projects/test-project-2/serviceAccounts/test-2@test-project-2.iam.gserviceaccount.com/keys/816fee7fb8592a09005d3f40042352cb906a25a1",
						"origin": "GOOGLE_PROVIDED",
						"type": "USER_MANAGED",
					}],
				},
			]},
		},
	]}}
}
