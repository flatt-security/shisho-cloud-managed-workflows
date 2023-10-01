package policy.googlecloud.credential.api_keys_restriction

import data.shisho

# Parameters
#################
# The following string slices are used to check if the allowed referrers are secure
# Please manage the below keyword sets to fit your needs!

forbidden_hosts := ["0.0.0.0", "0.0.0.0/0", "::0"]

referrer_forbidden_params := ["*"]

referrer_forbidden_prefixes := ["*."]

referrer_forbidden_postfixes := [".*"]

# Detection logic
#################

decisions[d] {
	project := input.googleCloud.projects[_]
	key := project.credentials.apiKeys[_]
	key.deletedAt == null

	d := shisho.decision.googlecloud.credential.api_keys_restriction({
		"allowed": has_enough_restriction(key),
		"subject": key.metadata.id,
		"payload": shisho.decision.googlecloud.credential.api_keys_restriction_payload({
			"restriction_type": restriction_type(key),
			"permissive_values": permissive_values(key),
		}),
	})
}

has_enough_restriction(key) {
	has_restriction_config(key)
	count(permissive_values(key)) == 0
} else := false

has_restriction_config(key) {
	key.restriction != null
	key.restriction.applicationRestriction != null
} else := false

restriction_type(key) := shisho.decision.googlecloud.credential.RESTRICTION_TYPE_IP_ADDRESS_RESTRICTION {
	key.restriction.applicationRestriction.__typename == "GoogleCloudAPIKeyApplicationServerRestriction"
} else := shisho.decision.googlecloud.credential.RESTRICTION_TYPE_REFERRER_RESTRICTION {
	key.restriction.applicationRestriction.__typename == "GoogleCloudAPIKeyApplicationBrowserRestriction"
} else := shisho.decision.googlecloud.credential.ANDROID_APP_RESTRICTION {
	key.restriction.applicationRestriction.__typename == "GoogleCloudAPIKeyApplicationAndroidRestriction"
} else := shisho.decision.googlecloud.credential.IOS_APP_RESTRICTION {
	key.restriction.applicationRestriction.__typename == "GoogleCloudAPIKeyApplicationIosRestriction"
} else := shisho.decision.googlecloud.credential.RESTRICTION_TYPE_NO_RESTRICTION

permissive_values(key) := [address |
	address := key.restriction.applicationRestriction.allowedIpAddresses[_]
	address == forbidden_hosts[_]
] {
	key.restriction.applicationRestriction.__typename == "GoogleCloudAPIKeyApplicationServerRestriction"
} else := [r |
	r := key.restriction.applicationRestriction.allowedReferrers[_]
	is_forbidden_referrer_restriction(r)
] {
	key.restriction.applicationRestriction.__typename == "GoogleCloudAPIKeyApplicationBrowserRestriction"
} else := []

is_forbidden_referrer_restriction(r) {
	r == referrer_forbidden_params[_]
} else {
	startswith(r, referrer_forbidden_prefixes[_])
} else {
	endswith(r, referrer_forbidden_postfixes[_])
} else := false
