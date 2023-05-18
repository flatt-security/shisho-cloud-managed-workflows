package policy.googlecloud.bigquery.dataset_encryption_cmek

import data.shisho
import future.keywords

test_whether_the_encryption_is_set_for_bigquery_datasets if {
	# check if the encryption is set for a Google Cloud BigQuery datasets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"bigQuery": {"datasets": [{
		"metadata": {"id": "google-cloud-bq-dataset|478528293314|kKDVkyN|RdNtzzA"},
		"defaultEncryptionConfiguration": {"kmsKeyName": "test-key-name"},
	}]}}]}}

	# check if the encryption is not set for a Google Cloud BigQuery datasets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"bigQuery": {"datasets": [{
		"metadata": {"id": "google-cloud-bq-dataset|478528293314|kKDVkyN|RdNtzzA"},
		"defaultEncryptionConfiguration": {"kmsKeyName": ""},
	}]}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"bigQuery": {"datasets": [{
		"metadata": {"id": "google-cloud-bq-dataset|478528293314|kKDVkyN|RdNtzzA"},
		"defaultEncryptionConfiguration": null,
	}]}}]}}
}
