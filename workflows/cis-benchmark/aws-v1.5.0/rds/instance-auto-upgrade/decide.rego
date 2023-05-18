package policy.aws.rds.instance_auto_upgrade

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	allowed := instance.autoMinorVersionUpgrade

	d := shisho.decision.aws.rds.instance_auto_upgrade({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_auto_upgrade_payload({"enabled": allowed}),
	})
}
