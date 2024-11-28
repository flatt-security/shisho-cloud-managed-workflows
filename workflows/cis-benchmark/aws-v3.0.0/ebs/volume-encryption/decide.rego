package policy.aws.ebs.volume_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	encryptions := account.ec2.defaultEbsEncryptions

	regions := disabled_regions(encryptions)

	d := shisho.decision.aws.ebs.volume_encryption_baseline({
		"allowed": count(regions) == 0,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.ebs.volume_encryption_baseline_payload({"disabled_regions": regions}),
	})
}

disabled_regions(default_ebs_encryptions) = x {
	x := [encryption.region |
		encryption := default_ebs_encryptions[_]
		encryption.enabled == false
	]
}
