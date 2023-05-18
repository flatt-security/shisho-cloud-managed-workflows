package policy.googlecloud.bigquery.dataset_encryption_cmek

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	dataset := project.bigQuery.datasets[_]

	d := shisho.decision.googlecloud.bigquery.dataset_encryption_cmek({
		"allowed": uses_default_key(dataset.defaultEncryptionConfiguration) == false,
		"subject": dataset.metadata.id,
		"payload": shisho.decision.googlecloud.bigquery.dataset_encryption_cmek_payload({
			"uses_default_key": uses_default_key(dataset.defaultEncryptionConfiguration),
			"key_name": key_name_or_empty(dataset.defaultEncryptionConfiguration),
		}),
	})
}

uses_default_key(ec) {
	key_name_or_empty(ec) == ""
} else = false {
	true
}

key_name_or_empty(ec) := ec.kmsKeyName {
	ec != null
} else := "" {
	true
}
