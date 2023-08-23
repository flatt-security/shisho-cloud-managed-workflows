package policy.aws.ecs.service

import data.shisho
import future.keywords

test_service_with_auto_ip_assignment_in_fargate_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		not shisho.decision.has_severity(d, shisho.decision.severity_info)
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"launchType": "FARGATE",
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|h4b-ecs-cluster|h4b-ecs-service"},
			"networkConfiguration": {"vpcConfiguration": {
				"subnets": [
					{"id": "subnet-09281c83ac0d0279b"},
					{"id": "subnet-0f581a6ce97387764"},
				],
				"securityGroups": [{"id": "sg-0b6ca13dca0878d10"}],
				"assignPublicIp": "ENABLED",
			}},
		}]},
	]}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		not shisho.decision.has_severity(d, shisho.decision.severity_info)
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"name": "h4b-ecs-service",
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|h4b-ecs-cluster|h4b-ecs-service"},
			"networkConfiguration": {"vpcConfiguration": {
				"subnets": [
					{"id": "subnet-09281c83ac0d0279b"},
					{"id": "subnet-0f581a6ce97387764"},
				],
				"securityGroups": [{"id": "sg-0b6ca13dca0878d10"}],
				"assignPublicIp": "ENABLED",
			}},
		}]},
	]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"name": "h4b-ecs-service",
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|h4b-ecs-cluster|h4b-ecs-service"},
			"networkConfiguration": {"vpcConfiguration": {
				"subnets": [
					{"id": "subnet-09281c83ac0d0279b"},
					{"id": "subnet-0f581a6ce97387764"},
				],
				"securityGroups": [{"id": "sg-0b6ca13dca0878d10"}],
				"assignPublicIp": "ENABLED",
			}},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		}]},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}

test_service_without_auto_public_ip_assignment_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"launchType": "FARGATE",
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|h4b-ecs-cluster|h4b-ecs-service"},
			"networkConfiguration": {"vpcConfiguration": {
				"subnets": [
					{"id": "subnet-09281c83ac0d0279b"},
					{"id": "subnet-0f581a6ce97387764"},
				],
				"securityGroups": [{"id": "sg-0b6ca13dca0878d10"}],
				"assignPublicIp": "DENIED",
			}},
		}]},
	]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"name": "h4b-ecs-service",
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|h4b-ecs-cluster|h4b-ecs-service"},
			"networkConfiguration": {"vpcConfiguration": {
				"subnets": [
					{"id": "subnet-09281c83ac0d0279b"},
					{"id": "subnet-0f581a6ce97387764"},
				],
				"securityGroups": [{"id": "sg-0b6ca13dca0878d10"}],
				"assignPublicIp": "DENIED",
			}},
		}]},
	]}}]}}
}

test_service_with_auto_ip_assignment_in_fargate_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.has_severity(d, shisho.decision.severity_info)
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"launchType": "EC2",
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|h4b-ecs-cluster|h4b-ecs-service"},
			"networkConfiguration": {"vpcConfiguration": {
				"subnets": [
					{"id": "subnet-09281c83ac0d0279b"},
					{"id": "subnet-0f581a6ce97387764"},
				],
				"securityGroups": [{"id": "sg-0b6ca13dca0878d10"}],
				"assignPublicIp": "ENABLED",
			}},
		}]},
	]}}]}}
}
