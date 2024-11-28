package policy.aws.ecs.task_fargate_version

import data.shisho
import future.keywords

test_fargate_tasks_with_version_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"launchType": "EC2",
			"platformVersion": "",
		}]},
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"platformVersion": "LATEST",
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-3"},
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"platformVersion": "LATEST",
		}]},
		{"services": []},
	]}}]}}
}

test_fargate_tasks_with_version_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"launchType": "EC2",
			"platformVersion": "",
		}]},
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"platformVersion": "1.4.0",
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-3"},
			"launchType": null,
			"capacityProviderStrategy": [{"name": "FARGATE"}],
			"platformVersion": "1.0.0",
		}]},
		{"services": []},
	]}}]}}
}
