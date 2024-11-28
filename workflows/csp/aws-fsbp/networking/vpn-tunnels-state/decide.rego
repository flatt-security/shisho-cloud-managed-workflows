package policy.aws.networking.vpn_tunnels_state

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	vpn_connection := account.network.vpnConnections[_]

	vgw_telemetry_list := vgw_telemetry_list_with_stattus(vpn_connection.vgwTelemetry)

	d := shisho.decision.aws.networking.vpn_tunnels_state({
		"allowed": allow_if_excluded(allowed_state(vgw_telemetry_list), vpn_connection),
		"subject": vpn_connection.metadata.id,
		"payload": shisho.decision.aws.networking.vpn_tunnels_state_payload({"vgw_telemetry_list": vgw_telemetry_list}),
	})
}

allowed_state(vgw_telemetry_list) = false {
	vgw_telemetry := vgw_telemetry_list[_]
	vgw_telemetry.status == "DOWN"
} else = true

vgw_telemetry_list_with_stattus(vgw_telemetry_list) = x {
	x := [{
		"outside_ip_address": vgw_telemetry.outsideIpAddress,
		"status": vgw_telemetry.status,
	} |
		vgw_telemetry := vgw_telemetry_list[_]
	]
} else = []

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
