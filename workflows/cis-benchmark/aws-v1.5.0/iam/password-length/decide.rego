package policy.aws.iam.password_length

import data.shisho

recommended_minimum_length := 14

decisions[d] {
	account := input.aws.accounts[_]

	current := required_length(account.iam.passwordPolicy)
	allowed := current >= recommended_minimum_length

	d := shisho.decision.aws.iam.password_length({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.password_length_payload({
			"current_minimum_length": current,
			"minimum_length_policy_recommendation": recommended_minimum_length,
		}),
	})
}

required_length(password_policy) := 8 {
	# `password_policy == null` means the account uses a default policy, and the default policy uses 8 characters as the minimum length.
	# https://docs.aws.amazon.com/ja_jp/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#default-policy-details
	password_policy == null
} else := password_policy.minimumPasswordLength {
	true
}
