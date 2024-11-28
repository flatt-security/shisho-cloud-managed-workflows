package policy.aws.iam.console_user_keys

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	# Prepare a map from a user name to a user resource ID in Shisho Cloud
	user_map := {user.name: user.metadata.id |
		user := account.iam.users[_]
	}

	content := account.iam.credentialReport.contents[_]
	subject := user_map[content.user]

	d := shisho.decision.aws.iam.console_user_keys({
		"allowed": has_console_password_and_unused_access_keys(content) == false,
		"subject": subject,
		"payload": shisho.decision.aws.iam.console_user_keys_payload({
			"has_console_password": content.passwordEnabled,
			"has_unused_console_password": has_unused_console_password(content),
			"has_access_key": has_access_keys(content),
			"has_unused_access_key": has_unused_access_keys(content),
		}),
	})
}

has_console_password_and_unused_access_keys(content) {
	content.passwordEnabled
	has_unused_access_keys(content)
} else = false

has_unused_console_password(content) {
	content.passwordEnabled
	content.passwordLastUsedAt == null
} else = false

has_access_keys(content) {
	content.accessKey1Active
} else {
	content.accessKey2Active
} else = false

has_unused_access_keys(content) {
	content.accessKey1Active
	content.accessKey1LastUsedAt == null
} else {
	content.accessKey2Active
	content.accessKey2LastUsedAt == null
} else = false
