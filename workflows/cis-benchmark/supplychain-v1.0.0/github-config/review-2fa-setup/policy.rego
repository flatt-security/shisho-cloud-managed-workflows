package policy.github.config.review_2fa_setup

import data.shisho

decisions[d] {
	org := input.github.organizations[_]
	allowed := org.requiresTwoFactorAuthentication == true

	d := shisho.decision.github.org_2fa_status({
		"allowed": allowed,
		"subject": org.metadata.id,
		"payload": shisho.decision.github.org_2fa_status_payload({"enabled": org.requiresTwoFactorAuthentication}),
	})
}
