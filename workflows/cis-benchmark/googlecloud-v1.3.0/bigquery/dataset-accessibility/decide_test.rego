package policy.googlecloud.bigquery.dataset_accessibility

import data.shisho
import future.keywords

test_whether_proper_accessibility_is_configured_for_bigquery_datasets if {
	# check if the excessive accessibility is not configured for a Google Cloud BigQuery datasets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": "354711641168",
		"bigQuery": {"datasets": [
			{
				"metadata": {"id": "google-cloud-bq-dataset|514893259785|test"},
				"access": [
					{
						"__typename": "GoogleCloudBigQueryDatasetAccessUserByEmail",
						"role": {"id": "OWNER"},
						"email": "test@email.com",
					},
					{
						"__typename": "GoogleCloudBigQueryDatasetAccessSpecialGroup",
						"role": {"id": "OWNER"},
						"name": "projectWriters",
					},
				],
			},
			{
				"metadata": {"id": "google-cloud-bq-dataset|514893259786|test"},
				"access": [],
			},
		]},
	}]}}

	# check if all users is accessible for a Google Cloud BigQuery datasets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": "354711641168",
		"bigQuery": {"datasets": [{
			"metadata": {"id": "google-cloud-bq-dataset|514893259785|test"},
			"access": [
				{
					"__typename": "GoogleCloudBigQueryDatasetAccessIamMember",
					"role": {"id": "WRITER"},
					"memberType": "allUsers",
				},
				{
					"__typename": "GoogleCloudBigQueryDatasetAccessSpecialGroup",
					"role": {"id": "OWNER"},
					"name": "projectWriters",
				},
			],
		}]},
	}]}}

	# check if all authenticated users is accessible for a Google Cloud BigQuery datasets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": "354711641168",
		"bigQuery": {"datasets": [{
			"metadata": {"id": "google-cloud-bq-dataset|514893259785|test"},
			"access": [
				{
					"__typename": "GoogleCloudBigQueryDatasetAccessSpecialGroup",
					"role": {"id": "WRITER"},
					"name": "allAuthenticatedUsers",
				},
				{
					"__typename": "GoogleCloudBigQueryDatasetAccessSpecialGroup",
					"role": {"id": "OWNER"},
					"name": "projectWriters",
				},
			],
		}]},
	}]}}
}
