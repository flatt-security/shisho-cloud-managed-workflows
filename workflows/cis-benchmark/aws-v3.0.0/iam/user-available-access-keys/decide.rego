package policy.aws.iam.user_available_access_keys

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	user = account.iam.users[_]

	keys := owned_access_keys(user.accessKeys)
	allowed := count(keys) <= 1

	d := shisho.decision.aws.iam.user_available_access_keys({
		"allowed": allowed,
		"subject": user.metadata.id,
		"payload": shisho.decision.aws.iam.user_available_access_keys_payload({"access_key_ids": keys}),
	})
}

owned_access_keys(access_keys) := x {
	x := [key.id |
		key := access_keys[_]
		key.status == "ACTIVE"
	]
}
