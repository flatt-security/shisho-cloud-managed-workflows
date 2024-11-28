package policy.aws.networking.sg_ingress_v4

import data.shisho

ports_to_deny = [
	22,
	3389,
]

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]

	g := vpc.securityGroups[_]
	allowed := has_insecure_rule(g.ipPermissionsIngress) == false
	d := shisho.decision.aws.networking.sg_ingress_v4({
		"allowed": allow_if_excluded(allowed, g),
		"subject": g.metadata.id,
		"payload": shisho.decision.aws.networking.sg_ingress_v4_payload({}),
		"severity": severity(g, allowed, account.network.networkInterfaces, vpc.acls),
	})
}

severity(sg, allowed, enis, acls) := shisho.decision.severity_info {
	allowed
} else = shisho.decision.severity_info {
	# If no ENIs have the SG, the severity is info.
	has_no_enis_with_sg(enis, sg)
	print("SG is not used", sg.id)
} else = shisho.decision.severity_info {
	# If all subnets of ENIs with the SG are private, the severity is info.
	has_no_enis_in_public_subnet(enis, sg)
	print("SG is not used in public subnet", sg.id)
} else = shisho.decision.severity_medium {
	# If all subnets of ENIs with the SG do not allow traffic from the internet, the severity is info.
	has_conflict_nacl_only(enis, acls, sg)
	print("SG has conflicting NACL entries", sg.id)
} else = shisho.decision.severity_high

has_no_enis_with_sg(enis, sg) := false {
	eni := enis[_]
	eni.securityGroups[_].id == sg.id
} else = true

has_no_enis_in_public_subnet(enis, sg) := false {
	eni := enis[_]
	eni.securityGroups[_].id == sg.id
	eni_is_in_public_subnet(eni)
} else = true

eni_is_in_public_subnet(eni) {
	r := eni.subnet.routeTable.routes[_]
	startswith(r.gatewayId, "igw-")
} else = false

# SG rules
###########
has_insecure_rule(rules) {
	rule := rules[_]
	range := rule.ipv4Ranges[_]
	range.cidrIpv4 == "0.0.0.0/0"

	p := ports_to_deny[_]
	rule_allows(rule.fromPort, rule.toPort, p)
} else = false

rule_allows(from, to, port) {
	from <= port
	port <= to
} else {
	from == 0
	to == 0
} else = false

# NACL
###########

# Even if the SG allows connection from 0.0.0.0/0,
# NACL may block the traffic.
#
# The following function will confirm ALL ENIs with the SG has the conflicting NACL entry,
# implying that traffic to ALL ENIs have the IPv4 range blocked by NACL.
#
# If there is any ENI with the SG that does not have the conflicting NACL entry (= allowing the traffic from 0.0.0.0/0),
# The following function will return false.
has_conflict_nacl_only(enis, acls, sg) := false {
	# If any of the subnets with ENIs with the SG,
	eni := enis[_]
	eni.securityGroups[_].id == sg.id
	subnet := eni.subnet

	# the associated NACL does not have the conflicting entry,
	acl := acls[_]
	acl.associations[_].subnetId == subnet.id
	not nacl_has_conflict_entry(acl)
	# ... we should return false, because there is at least one bad ENI with the SG.
} else = true

# The following function will confirm the traffic some part of 0.0.0.0/0 can be blocked by NACL.
# If there is any IPv4 address that is blocked by NACL, we should return true.
#
# The following rule may lead to false positive b/c we do not consider the rule priority.
# In NACL rules, the rule with smaller rule number has higher priority, and the latter rule will not be evaluated.
nacl_has_conflict_entry(nacl) {
	ruleNumber := nacl_has_conflict_entry_deny(nacl)
	ruleNumber != -1
} else = false

nacl_has_conflict_entry_deny(nacl) := min(rn) {
	rn := [e.ruleNumber |
		e := nacl.entries[_]
		e.type == "INGRESS"
		port_range_includes(e.portRange, ports_to_deny[_])
		e.ruleAction == "DENY"
		e.ruleNumber < 32767 # 32767 or higher is AWS internal IDs
	]
	count(rn) > 0
} else = -1

port_range_includes(r, port) {
	r.from == 0
	r.to == 0
} else {
	r.from <= port
	port <= r.to
} else = false

# Misc
###########
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
