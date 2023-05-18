package policy.googlecloud.iam.service_account_key

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	account := project.iam.serviceAccounts[_]
	
	keys := user_managed_keys(account.keys)
	allowed := count(keys) == 0

	d := shisho.decision.googlecloud.iam.service_account_key({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.googlecloud.iam.service_account_key_payload({"keys": keys}),
	})
}

user_managed_keys(keys) := x {
	x := [name |
		key := keys[_]
		key.type == "USER_MANAGED"
		name := key.name
	]
}
