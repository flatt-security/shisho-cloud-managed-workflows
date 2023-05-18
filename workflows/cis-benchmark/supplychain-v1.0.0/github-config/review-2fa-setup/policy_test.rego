package policy.github.config.review_2fa_setup

import data.shisho
import future.keywords

test_whether_two_factor_authentication_is_configured if {
	# check whether a two factor authentication is required
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{
		"metadata": {"id": "dummy"},
		"requiresTwoFactorAuthentication": true,
	}]}}

	# check whether a two factor authentication is not required
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{
		"metadata": {"id": "dummy"},
		"requiresTwoFactorAuthentication": false, # = members can access an organization without the two factor authentication
	}]}}
}
