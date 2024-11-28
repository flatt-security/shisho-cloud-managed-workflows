package policy.aws.networking.fp_stateless_action

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	vpc := account.network.vpcs[_]
	firewall := vpc.firewalls[_]

	default_actions := firewall.firewallPolicy.statelessDefaultActions

	d := shisho.decision.aws.networking.fp_stateless_action({
		"allowed": allow_if_excluded(allowed(default_actions), firewall),
		"subject": firewall.metadata.id,
		"payload": shisho.decision.aws.networking.fp_stateless_action_payload({"stateless_default_actions": default_actions}),
	})
}

allowed(stateless_default_actions) {
	action := stateless_default_actions[_]
	action in ["aws:drop", "aws:forward_to_sfe"]
} else = false

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
