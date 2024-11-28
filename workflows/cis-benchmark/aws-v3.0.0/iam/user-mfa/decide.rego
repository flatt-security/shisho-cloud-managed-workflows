package policy.aws.iam.user_mfa

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	# Prepare a map from a user name to a user resource ID in Shisho Cloud
	user_map := {user.name: user.metadata.id |
		user := account.iam.users[_]
	}
	content := account.iam.credentialReport.contents[_]
	subject := user_map[content.user]

	d := shisho.decision.aws.iam.user_mfa({
		"allowed": allowed(content),
		"subject": subject,
		"payload": shisho.decision.aws.iam.user_mfa_payload({
			"has_console_password": content.passwordEnabled,
			"mfa_active": content.mfaActive,
		}),
	})
}

allowed(content) {
	# if the console password is set, MFA should be active.
	content.passwordEnabled == true
	content.mfaActive == true
} else {
	# if the console password is not set, MFA is not required.
	content.passwordEnabled == false
} else := false
