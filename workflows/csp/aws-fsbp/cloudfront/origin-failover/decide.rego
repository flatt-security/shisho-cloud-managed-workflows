package policy.aws.cloudfront.origin_failover

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	groups := origin_groups(dist.originGroups)

	d := shisho.decision.aws.cloudfront.origin_failover({
		"allowed": allow_if_excluded(has_origns(groups), dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.origin_failover_payload({"origin_groups": groups}),
	})
}

has_origns(groups) {
	group := groups[_]
	count(group.origins) > 1
} else = false

origin_groups(originGroups) := x {
	x := [{"id": group.id, "origins": origin_group_members(group.members)} |
		group := originGroups[_]
	]
} else := []

origin_group_members(members) := x {
	x := [member.originId |
		member := members[_]
	]
} else := []

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
