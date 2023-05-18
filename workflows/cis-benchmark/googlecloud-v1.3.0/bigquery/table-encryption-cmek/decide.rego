package policy.googlecloud.bigquery.table_encryption_cmek

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	dataset := project.bigQuery.datasets[_]
	table := dataset.tables[_]

	d := shisho.decision.googlecloud.bigquery.table_encryption_cmek({
		"allowed": uses_default_key(table.encryptionConfiguration) == false,
		"subject": table.metadata.id,
		"payload": shisho.decision.googlecloud.bigquery.table_encryption_cmek_payload({
			"uses_default_key": uses_default_key(table.encryptionConfiguration),
			"key_name": key_name_or_empty(table.encryptionConfiguration),
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
