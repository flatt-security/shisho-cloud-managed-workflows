package policy.aws.networking.sg_ingress_v6

import data.shisho
import future.keywords

test_whether_the_default_groups_exist_for_security_groups if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"network": {"vpcs": [{"securityGroups": [
		{
			"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-0c3843ad3c833ccf9"},
			"ipPermissionsIngress": [{
				"fromPort": 22,
				"toPort": 22,
				"ipv4Ranges": [],
				"ipv6Ranges": [{"cidrIpv6": "::/0"}],
			}],
		},
		{
			"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-06f32151576608861"},
			"ipPermissionsIngress": [{
				"fromPort": 0,
				"toPort": 0,
				"ipv4Ranges": [],
				"ipv6Ranges": [],
			}],
		},
	]}]}}]}}
}
