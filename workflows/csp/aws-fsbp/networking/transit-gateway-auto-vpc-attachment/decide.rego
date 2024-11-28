package policy.aws.networking.transit_gateway_auto_vpc_attachment

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	gateway := account.network.transitGateways[_]

	allowed := gateway.options.autoAcceptSharedAttachments == "DISABLE"

	d := shisho.decision.aws.networking.transit_gateway_auto_vpc_attachment({
		"allowed": allow_if_excluded(allowed, gateway),
		"subject": gateway.metadata.id,
		"payload": shisho.decision.aws.networking.transit_gateway_auto_vpc_attachment_payload({"auto_accept_shared_attachments_disabled": allowed}),
	})
}

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
