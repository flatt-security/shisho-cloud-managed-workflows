package policy.aws.rds.instance_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	allowed := instance.storageEncrypted

	d := shisho.decision.aws.rds.instance_encryption({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_encryption_payload({"enabled": allowed}),
	})
}
