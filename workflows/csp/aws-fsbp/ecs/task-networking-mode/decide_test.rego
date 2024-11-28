package policy.aws.ecs.task_networking_mode

import data.shisho
import future.keywords

test_network_mode_reviewed if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"taskDefinition": {"networkMode": "HOST"},
			"tags": [],
		}]},
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"taskDefinition": {"networkMode": "HOST"},
			"tags": [],
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-3"},
			"taskDefinition": {"networkMode": "HOST"},
			"tags": [],
		}]},
	]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"taskDefinition": {"networkMode": "BRIDGE"},
			"tags": [],
		}]},
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"taskDefinition": {"networkMode": "AWSVPC"},
			"tags": [],
		}]},
		{"services": []},
	]}}]}}
}
