package policy.aws.ecs.task_process_namespace

import data.shisho
import future.keywords

test_task_definitions_with_namespace_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"taskDefinition": {"pidMode": "TASK"},
		}]},
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"taskDefinition": {"pidMode": "TASK"},
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-3"},
			"taskDefinition": {"pidMode": ""},
		}]},
	]}}]}}
}

test_task_definitions_with_namespace_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"taskDefinition": {"pidMode": "HOST"},
		}]},
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"taskDefinition": {"pidMode": "HOST"},
		}]},
		{"services": []},
	]}}]}}
}
