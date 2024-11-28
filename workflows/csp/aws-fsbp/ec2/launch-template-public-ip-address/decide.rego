package policy.aws.ec2.launch_template_public_ip_address

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	template := account.ec2.launchTemplates[_]

	interfaces := network_interfaces_with_public_ip_state(template.defaultVersion.details.networkInterfaces)

	d := shisho.decision.aws.ec2.launch_template_public_ip_address({
		"allowed": allow_if_excluded(is_not_publicly_accessible(interfaces), template),
		"subject": template.metadata.id,
		"payload": shisho.decision.aws.ec2.launch_template_public_ip_address_payload({
			"default_version": template.defaultVersion.number,
			"network_interfaces": interfaces,
		}),
	})
}

is_not_publicly_accessible(interfaces) = false {
	interface := interfaces[_]
	interface.publicly_accessible == true
} else = true

network_interfaces_with_public_ip_state(network_interfaces) = x {
	x := [{
		"id": interface_name(network_interface),
		"public_ip": public_ip,
		"publicly_accessible": is_publicly_accessible(public_ip, network_interface.associatePublicIpAddress),
	} |
		network_interface := network_interfaces[_]
		public_ip := interface_public_ip(network_interface)
	]
} else = []

is_publicly_accessible(ip, associate_public_ip_address) {
	[associate_public_ip_address, ip != ""][_] == true
} else = false

interface_name(network_interface) := "NEW_INTERFACE" {
	network_interface.networkInterface == null
} else = network_interface.networkInterface.id

interface_public_ip(network_interface) := network_interface.networkInterface.association.publicIp {
	network_interface.networkInterface.association != null
} else = ""

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
