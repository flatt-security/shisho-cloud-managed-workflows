package policy.aws.rds.instance_accessibility

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	instance := account.rds.instances[_]

	allowed := is_allowed(instance.publiclyAccessible, instance.subnetGroup.vpc.routeTables) == false

	d := shisho.decision.aws.rds.instance_accessibility({
		"allowed": allowed,
		"subject": instance.metadata.id,
		"payload": shisho.decision.aws.rds.instance_accessibility_payload({"is_publicly_accessible": allowed == false}),
	})
}

is_allowed(publicly_accessible, route_tables) {
	publicly_accessible == true

	table := route_tables[_]
	route := table.routes[_]
	startswith(route.gatewayId, "igw-")
	route.destinationCidrBlock == "0.0.0.0/0"
} else = false {
	true
}
