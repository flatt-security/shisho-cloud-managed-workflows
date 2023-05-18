package policy.aws.efs.volume_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	filesystem := account.efs.fileSystems[_]

	encrypted := filesystem.encrypted

	d := shisho.decision.aws.efs.volume_encryption({
		"allowed": encrypted,
		"subject": filesystem.metadata.id,
		"payload": shisho.decision.aws.efs.volume_encryption_payload({"encrypted": encrypted}),
	})
}
