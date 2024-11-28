package policy.aws.networking.default_sg_ip_restriction

import data.shisho
import future.keywords

test_ip_restriction_of_default_security_groups_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"id": "vpc-0fc5a1285f13fab17",
			"securityGroups": [{
				"metadata": {
					"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fc5a1285f13fab17|sg-0b6ca13dca0878d10",
					"displayName": "sg-0b6ca13dca0878d10",
				},
				"name": "default",
				"ipPermissionsIngress": [],
				"ipPermissionsEgress": [],
			}],
		},
		{
			"id": "vpc-0fb9667dee2b36e00",
			"securityGroups": [
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-082d728a5b0669e80",
						"displayName": "sg-082d728a5b0669e80",
					},
					"name": "ecs-test-EcsSecurityGroup-1JDG3O0E5TE4M",
					"ipPermissionsIngress": [
						{
							"fromPort": 80,
							"toPort": 80,
						},
						{
							"fromPort": 22,
							"toPort": 22,
						},
						{
							"fromPort": 31000,
							"toPort": 61000,
						},
					],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-0c3843ad3c833ccf9",
						"displayName": "sg-0c3843ad3c833ccf9",
					},
					"name": "launch-wizard-1",
					"ipPermissionsIngress": [{
						"fromPort": 22,
						"toPort": 22,
					}],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-01960f657835264b4",
						"displayName": "sg-01960f657835264b4",
					},
					"name": "eks-cluster-sg-test-cluster-1-1896257955",
					"ipPermissionsIngress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-07af9b423ae9ee1cb",
						"displayName": "sg-07af9b423ae9ee1cb",
					},
					"name": "aws-cloud9-h4b-ecs-83758eaee3c846398fb85ce4607f79ed-InstanceSecurityGroup-UWX3R9HGGILH",
					"ipPermissionsIngress": [],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-06f32151576608861",
						"displayName": "sg-06f32151576608861",
					},
					"name": "default",
					"ipPermissionsIngress": [],
					"ipPermissionsEgress": [],
				},
			],
		},
	]}}]}}
}

test_ip_restriction_of_default_security_groups_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"id": "vpc-0fc5a1285f13fab17",
			"securityGroups": [{
				"metadata": {
					"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fc5a1285f13fab17|sg-0b6ca13dca0878d10",
					"displayName": "sg-0b6ca13dca0878d10",
				},
				"name": "default",
				"ipPermissionsIngress": [
					{
						"fromPort": 80,
						"toPort": 80,
					},
					{
						"fromPort": 0,
						"toPort": 0,
					},
				],
				"ipPermissionsEgress": [{
					"fromPort": 0,
					"toPort": 0,
				}],
			}],
		},
		{
			"id": "vpc-0fb9667dee2b36e00",
			"securityGroups": [
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-082d728a5b0669e80",
						"displayName": "sg-082d728a5b0669e80",
					},
					"name": "ecs-test-EcsSecurityGroup-1JDG3O0E5TE4M",
					"ipPermissionsIngress": [
						{
							"fromPort": 80,
							"toPort": 80,
						},
						{
							"fromPort": 22,
							"toPort": 22,
						},
						{
							"fromPort": 31000,
							"toPort": 61000,
						},
					],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-0c3843ad3c833ccf9",
						"displayName": "sg-0c3843ad3c833ccf9",
					},
					"name": "launch-wizard-1",
					"ipPermissionsIngress": [{
						"fromPort": 22,
						"toPort": 22,
					}],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-01960f657835264b4",
						"displayName": "sg-01960f657835264b4",
					},
					"name": "eks-cluster-sg-test-cluster-1-1896257955",
					"ipPermissionsIngress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-07af9b423ae9ee1cb",
						"displayName": "sg-07af9b423ae9ee1cb",
					},
					"name": "aws-cloud9-h4b-ecs-83758eaee3c846398fb85ce4607f79ed-InstanceSecurityGroup-UWX3R9HGGILH",
					"ipPermissionsIngress": [],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
				{
					"metadata": {
						"id": "aws-vpc-secuirty-group|ap-northeast-1|vpc-0fb9667dee2b36e00|sg-06f32151576608861",
						"displayName": "sg-06f32151576608861",
					},
					"name": "default",
					"ipPermissionsIngress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
					"ipPermissionsEgress": [{
						"fromPort": 0,
						"toPort": 0,
					}],
				},
			],
		},
	]}}]}}
}
