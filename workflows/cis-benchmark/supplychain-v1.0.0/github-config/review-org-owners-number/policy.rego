package policy.github.config.review_org_owners_number

import data.shisho

# you should not assign too many admins for organizations
# please adjust the value depends on the size of your team
max_admin_num = 2

admins(org) = x {
	x = [member.login | member := org.members[_]; member.role == "OWNER"]
}

decisions[d] {
	org := input.github.organizations[_]
	allowed := count(admins(org)) <= max_admin_num

	d := shisho.decision.github.org_owners({
		"allowed": allowed,
		"subject": org.metadata.id,
		"payload": shisho.decision.github.org_owners_payload({"admins": admins(org)}),
	})
}
