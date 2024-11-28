package policy.aws.s3.account_public_access_block

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	enabled := account_level_public_access(account)
	d := shisho.decision.aws.s3.account_public_access_block({
		"allowed": enabled,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.s3.account_public_access_block_payload({"enabled": enabled}),
	})
}

account_level_public_access(account) {
	account.s3.publicAccessBlockConfiguration != null
	config := account.s3.publicAccessBlockConfiguration

	config.blockPublicAcls == true
	config.blockPublicPolicy == true
	config.ignorePublicAcls == true
	config.restrictPublicBuckets == true
} else = false
