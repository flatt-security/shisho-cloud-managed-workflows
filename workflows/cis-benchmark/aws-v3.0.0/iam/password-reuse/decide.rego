package policy.aws.iam.password_reuse

import data.shisho

reuse_prevention_recommendation := 24

decisions[d] {
	account := input.aws.accounts[_]

	current := reuse_prevention(account.iam.passwordPolicy)
	allowed := current >= reuse_prevention_recommendation

	d := shisho.decision.aws.iam.password_reuse({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.password_reuse_payload({
			"reuse_prevention_policy_recommendation": reuse_prevention_recommendation,
			"current_reuse_prevention": current,
		}),
	})
}

reuse_prevention(policy) := 0 {
	# `policy == null` means the account uses a default policy, and the default policy does not enforce password history policy.
	# https://docs.aws.amazon.com/ja_jp/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#default-policy-details
	policy == null
} else := policy.passwordReusePrevention
