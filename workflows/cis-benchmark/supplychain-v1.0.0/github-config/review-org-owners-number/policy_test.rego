package policy.github.config.review_org_owners_number

import data.shisho
import future.keywords

dummy_account := {
	"login": "dummy",
	"role": "OWNER",
	"metadata": {"id": "dummy-account"},
}

test_whether_appropriate_number_of_administrators_is_assigned_to_organizations if {
	# check whether the number of repository admin's is `max_admin_num` or less
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{
		"metadata": {"id": "dummy"},
		"members": [dummy_account, dummy_account], # there are 2 admins and it is `max_admin_num`
	}]}}

	# check whether the number of repository admin's is greater than `max_admin_num`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{
		"metadata": {"id": "dummy"},
		"members": [dummy_account, dummy_account, dummy_account, dummy_account], # there are 4 admins and it is greater than `max_admin_num`
	}]}}
}
