package policy.aws.iam.root_user_key

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	has_access_key := find_root_access_key_field(account.iam.accountSummary.summaryMap)
	allowed := has_access_key == false

	d := shisho.decision.aws.iam.root_user_key({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.root_user_key_payload({"root_has_access_keys": has_access_key}),
	})
}

find_root_access_key_field(summary) {
	field := summary[_]

	# NOTE: This name `AccountAccessKeysPresent` is a bit misleading. It's actually the number of keys only for the root user.
	field.key == "AccountAccessKeysPresent"

	field.value > 0
} else = false
