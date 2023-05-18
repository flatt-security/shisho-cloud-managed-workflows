package policy.googlecloud.sql.instance_public_ip

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.cloudSql.instances[_]

	has_ip := has_public_ip(instance.instanceType, instance.ipAddresses)

	d := shisho.decision.googlecloud.sql.instance_public_ip({
		"allowed": has_ip == false,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.sql.instance_public_ip_payload({"has_public_ip": has_ip}),
	})
}

has_public_ip(instance_type, ip_addresses) {
	instance_type != "READ_REPLICA_INSTANCE"

	ip_address := ip_addresses[_]

	# "PRIMARY" represents a public IP in this context.
	# https://cloud.google.com/sql/docs/mysql/admin-api/rest/v1beta4/instances#sqlipaddresstype
	ip_address.ipAddressType == "PRIMARY"
} else = false
