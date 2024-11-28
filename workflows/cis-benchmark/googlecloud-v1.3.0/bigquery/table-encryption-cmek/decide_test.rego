package policy.googlecloud.bigquery.table_encryption_cmek

import data.shisho
import future.keywords

test_whether_the_encryption_is_set_for_bigquery_tables if {
	# check if the encryption is set for a Google Cloud BigQuery tables
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"name": "test-table",
		"metadata": {"id": "google-cloud-bq-table|478528293314|kKDVkyN|RdNtzzA"},
		"encryptionConfiguration": {"kmsKeyName": "test-key-name"},
	}

	# check if the encryption is not set for a Google Cloud BigQuery tables
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"name": "test-table",
		"metadata": {"id": "google-cloud-bq-table|478528293314|kKDVkyN|RdNtzzA"},
		"encryptionConfiguration": {"kmsKeyName": ""},
	}
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {
		"name": "test-table",
		"metadata": {"id": "google-cloud-bq-table|478528293314|kKDVkyN|RdNtzzA"},
		"encryptionConfiguration": null,
	}
}
