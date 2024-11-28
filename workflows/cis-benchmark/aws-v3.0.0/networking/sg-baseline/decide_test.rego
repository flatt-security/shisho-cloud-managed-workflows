package policy.aws.networking.sg_baseline

import data.shisho
import future.keywords

test_whether_the_ip_permissions_for_default_security_groups_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{"securityGroups": [{
			"metadata": {
				"id": "aws-vpc-secuirty-group|eu-west-3|vpc-06bcfc98ac7777777|sg-08aefa50d1f7777777",
				"displayName": "sg-08aefa50d1f7777777",
			},
			"name": "default",
			"ipPermissionsIngress": [],
			"ipPermissionsEgress": [],
			"tags": [],
		}]},
		{"securityGroups": [{
			"metadata": {
				"id": "aws-vpc-secuirty-group|eu-central-1|vpc-06bcfc98ac7777778|sg-08aefa50d1f7777778",
				"displayName": "sg-08aefa50d1f7777778",
			},
			"name": "default",
			"ipPermissionsIngress": [],
			"ipPermissionsEgress": [],
			"tags": [],
		}]},
	]}}]}}
}

test_whether_the_ip_permissions_for_default_security_groups_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{"securityGroups": [{
			"metadata": {
				"id": "aws-vpc-secuirty-group|eu-west-3|vpc-06bcfc98ac7777777|sg-08aefa50d1f7777777",
				"displayName": "sg-08aefa50d1f7777777",
			},
			"name": "default",
			"ipPermissionsIngress": [{
				"ipProtocol": "all",
				"fromPort": 0,
				"toPort": 0,
			}],
			"ipPermissionsEgress": [{
				"ipProtocol": "all",
				"fromPort": 0,
				"toPort": 0,
			}],
			"tags": [],
		}]},
		{"securityGroups": [{
			"metadata": {
				"id": "aws-vpc-secuirty-group|eu-central-1|vpc-06bcfc98ac7777778|sg-08aefa50d1f7777778",
				"displayName": "sg-08aefa50d1f7777778",
			},
			"name": "default",
			"ipPermissionsIngress": [{
				"ipProtocol": "all",
				"fromPort": 0,
				"toPort": 0,
			}],
			"ipPermissionsEgress": [{
				"ipProtocol": "all",
				"fromPort": 0,
				"toPort": 0,
			}],
			"tags": [],
		}]},
		{"securityGroups": [{
			"metadata": {
				"id": "aws-vpc-secuirty-group|eu-central-1|vpc-06bcfc98ac7777779|sg-08aefa50d1f7777779",
				"displayName": "sg-08aefa50d1f7777779",
			},
			"name": "default",
			"ipPermissionsIngress": [{
				"ipProtocol": "all",
				"fromPort": 0,
				"toPort": 0,
			}],
			"ipPermissionsEgress": [{
				"ipProtocol": "all",
				"fromPort": 0,
				"toPort": 0,
			}],
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		}]},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
