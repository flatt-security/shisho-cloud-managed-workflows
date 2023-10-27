package policy.aws.networking.sg_ingress_v4

import data.shisho
import future.keywords

test_whether_the_port_ranges_are_configured_properly_for_security_groups if {
	# check if the port ranges are configured properly for security groups
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{"securityGroups": [
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b77777|sg-06f32151576611111"},
				"name": "default",
				"ipPermissionsIngress": [{
					"fromPort": 0,
					"toPort": 0,
					"ipv4Ranges": [],
				}],
			},
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b77777|sg-0c3843ad3c8322222"},
				"name": "test-group-1",
				"ipPermissionsIngress": [{
					"fromPort": 80,
					"toPort": 80,
					"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
				}],
			},
		]},
		{"securityGroups": [
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-06dc8a2abafd88888|sg-09951a05c41e33333"},
				"name": "default",
				"ipPermissionsIngress": [{
					"fromPort": 0,
					"toPort": 0,
					"ipv4Ranges": [],
				}],
			},
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-06dc8a2abafd88888|sg-0440545548fc44444"},
				"name": "test-group-2",
				"ipPermissionsIngress": [{
					"fromPort": 80,
					"toPort": 80,
					"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
				}],
			},
		]},
	]}}]}}

	# check if the port ranges are not configured properly for security groups
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{"securityGroups": [
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b77777|sg-06f32151576611111"},
				"name": "default",
				"ipPermissionsIngress": [{
					"fromPort": 0,
					"toPort": 0,
					"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
				}],
			},
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b77777|sg-0c3843ad3c8322222"},
				"name": "test-group-1",
				"ipPermissionsIngress": [{
					"fromPort": 22,
					"toPort": 22,
					"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
				}],
			},
		]},
		{"securityGroups": [
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-06dc8a2abafd88888|sg-09951a05c41e33333"},
				"name": "default",
				"ipPermissionsIngress": [{
					"fromPort": 3389,
					"toPort": 3389,
					"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
				}],
			},
			{
				"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-06dc8a2abafd88888|sg-0440545548fc44444"},
				"name": "test-group-2",
				"ipPermissionsIngress": [{
					"fromPort": 3389,
					"toPort": 3389,
					"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
				}],
			},
		]},
	]}}]}}

	# check tag_exceptions works
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"network": {"vpcs": [{"securityGroups": [
		{
			"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b77777|sg-06f32151576611111"},
			"name": "default",
			"ipPermissionsIngress": [{
				"fromPort": 0,
				"toPort": 0,
				"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
			}],
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b77777|sg-0c3843ad3c8322222"},
			"name": "test-group-1",
			"ipPermissionsIngress": [{
				"fromPort": 22,
				"toPort": 22,
				"ipv4Ranges": [{"cidrIpv4": "0.0.0.0/0"}],
			}],
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
