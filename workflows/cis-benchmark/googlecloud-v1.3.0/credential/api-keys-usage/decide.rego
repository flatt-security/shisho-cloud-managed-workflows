package policy.googlecloud.credential.api_keys_usage

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	api_keys := active_api_keys(project.credentials.apiKeys)

	d := shisho.decision.googlecloud.credential.api_keys_usage({
		"allowed": count(api_keys) == 0,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.credential.api_keys_usage_payload({"api_key_names": api_keys}),
	})
}

active_api_keys(api_keys) := x {
	x := [api_key.name |
		api_key := api_keys[_]
		api_key.deletedAt == null
	]
} else := []
