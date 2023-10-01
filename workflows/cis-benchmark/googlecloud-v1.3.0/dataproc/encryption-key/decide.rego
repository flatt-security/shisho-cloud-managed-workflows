package policy.googlecloud.dataproc.encryption_key

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	cluster := project.dataproc.clusters[_]

	allowed := cluster.configuration.encryptionConfiguration.gcePdKmsKeyName != ""

	d := shisho.decision.googlecloud.dataproc.encryption_key({
		"allowed": allowed,
		"subject": cluster.metadata.id,
		"payload": shisho.decision.googlecloud.dataproc.encryption_key_payload({"has_customer_managed_key": allowed}),
	})
}
