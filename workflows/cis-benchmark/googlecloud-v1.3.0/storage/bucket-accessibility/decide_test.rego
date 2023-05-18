package policy.googlecloud.storage.bucket_accessibility

import data.shisho
import future.keywords

test_whether_proper_accessibility_is_configured_for_storage_buckets if {
	# check if the excessive accessibility is not configured by an ACL list for Google Cloud Storage buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudStorage": {"buckets": [
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259785|test-1"},
			"acl": [
				{
					"role": "OWNER",
					"entity": "test@email.com",
				},
				{
					"role": "OWNER",
					"entity": "projectWriters",
				},
			],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "projectEditor:fslp-dev"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259785|test-2"},
			"acl": [],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "projectEditor:fslp-dev"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259785|test-3"},
			"acl": [
				{
					"role": "OWNER",
					"entity": "test@email.com",
				},
				{
					"role": "OWNER",
					"entity": "projectWriters",
				},
			],
			"iamPolicy": {"bindings": []},
		},
	]}}]}}

	# check if all users is accessible by an ACL list for Google Cloud Storage buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 6 with input as {"googleCloud": {"projects": [{"cloudStorage": {"buckets": [
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259785|test"},
			"acl": [
				{
					"role": "WRITER",
					"entity": "allUsers",
				},
				{
					"role": "OWNER",
					"entity": "projectWriters",
				},
			],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "projectEditor:fslp-dev"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259786|test"},
			"acl": [
				{
					"role": "WRITER",
					"entity": "allAuthenticatedUsers",
				},
				{
					"role": "OWNER",
					"entity": "projectWriters",
				},
			],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "projectEditor:fslp-dev"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259787|test"},
			"acl": [
				{
					"role": "WRITER",
					"entity": "allUsers",
				},
				{
					"role": "OWNER",
					"entity": "projectWriters",
				},
			],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "allAuthenticatedUsers"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259788|test"},
			"acl": [
				{
					"role": "WRITER",
					"entity": "projectWriters",
				},
				{
					"role": "OWNER",
					"entity": "projectOwners",
				},
			],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "allUsers"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259789|test"},
			"acl": [],
			"iamPolicy": {"bindings": [{
				"members": [
					{"id": "allUsers"},
					{"id": "projectOwner:fslp-dev"},
				],
				"role": "roles/storage.legacyBucketOwner",
			}]},
		},
		{
			"metadata": {"id": "google-cloud-bq-dataset|514893259780|test"},
			"acl": [
				{
					"role": "WRITER",
					"entity": "allUsers",
				},
				{
					"role": "OWNER",
					"entity": "projectWriters",
				},
			],
			"iamPolicy": {"bindings": []},
		},
	]}}]}}
}
