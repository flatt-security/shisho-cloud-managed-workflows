package policy.aws.flatt.elb.backend_sg

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	# This rule is for ALB
	lb := account.elb.loadBalancers[_]
	lb.__typename == "AWSELBApplicationLoadBalancer"

	# The rule is on the backend EC2 instance
	instance := lb.targetGroups[_].targetInstances[_]

	# If the connection for the backend instance has ingress rules NOT from the ALB, then it's risky.
	instance_sgs := sgs_for_instance(instance, lb.vpc.securityGroups)
	paths := exceptional_paths(instance_sgs, lb.securityGroups)

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1",
		"kind": "aws_elb_transport_sg",
		"subject": instance.metadata.id,
		"locator": "",
		"severity": shisho.decision.severity_medium,
		"allowed": count(paths) == 0,
		"payload": json.marshal({
			"instance_security_groups": [sg.id | sg := instance_sgs[_]],
			"exceptional_paths": paths,
		}),
	})
}

# List up all security groups that are associated with the instance
sgs_for_instance(instance, sgs) = [sg |
	sg := sgs[_]
	sg.id = instance.securityGroups[_].id
]

# List up the ingress rules that allow the connection NOT from the ALB
exceptional_paths(sgs, alb_sgs) = [{
	"sg_id": sg.id,
	"port_from": r.fromPort,
	"port_to": r.toPort,
	"accessible_from": x,
} |
	sg := sgs[_]
	r := sg.ipPermissionsIngress[_]
	x := allow_connection_not_from_alb(r, alb_sgs)
	x != false
]

# Check if the security group allows the connection from the ALB
allow_connection_not_from_alb(r, alb_sgs) := x {
	x := r.ipv4Ranges[_].cidrIpv4
	x != ""
} else {
	x := r.ipv6Ranges[_].cidrIpv6
	x != ""
} else {
	x := r.prefixListIds[_].id
	x != ""
} else {
	g := r.userIdGroupPairs[_]
	not is_alb_sg(g.id, alb_sgs)
	x := g.groupId
} else := false

is_alb_sg(gid, alb_sgs) {
	gid == alb_sgs[_].groupId
} else = false
