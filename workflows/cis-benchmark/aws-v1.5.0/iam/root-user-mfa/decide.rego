package policy.aws.iam.root_user_mfa

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	is_enabled := find_mfa_field(account.iam.accountSummary.summaryMap)
	allowed := is_enabled

	d := shisho.decision.aws.iam.root_user_mfa({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.root_user_mfa_payload({"mfa_enabled": is_enabled}),
	})
}

find_mfa_field(summary) {
	field := summary[_]
	field.key == "AccountMFAEnabled"
	field.value == 1
} else = false {
	true
}
