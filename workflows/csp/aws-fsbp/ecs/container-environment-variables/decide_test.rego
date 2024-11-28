package policy.aws.ecs.container_environment_variables

import data.shisho
import future.keywords

test_task_definitions_with_namespace_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"taskDefinition": {"containerDefinitions": [
				{
					"name": "simple-app",
					"environment": [
						{"name": "TEST_ENV1"},
						{"name": "TEST_ENV2"},
					],
				},
				{
					"name": "busybox",
					"environment": [{"name": "TEST_ENV2"}],
				},
			]},
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
			"taskDefinition": {"containerDefinitions": [{
				"name": "apache-helloworld",
				"environment": [
					{"name": "TEST_ENV1"},
					{"name": "TEST_ENV2"},
				],
			}]},
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-3"},
			"taskDefinition": {"containerDefinitions": [{}]},
		}]},
		{"services": []},
	]}}]}}
}

test_task_definitions_with_namespace_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
			"taskDefinition": {"containerDefinitions": [
				{
					"name": "simple-app",
					"environment": [
						{"name": "AWS_ACCESS_KEY_ID"},
						{"name": "AWS_SECRET_ACCESS_KEY"},
					],
				},
				{
					"name": "busybox",
					"environment": [
						{"name": "ECS_ENGINE_AUTH_DATA"},
						{"name": "TEST_ENV2"},
					],
				},
			]},
		}]},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-4"},
			"taskDefinition": {"containerDefinitions": [{
				"name": "ecs-win-test-awsecssample",
				"environment": [
					{"name": "AWS_ACCESS_KEY_ID"},
					{"name": "AWS_SECRET_ACCESS_KEY"},
					{"name": "ECS_ENGINE_AUTH_DATA"},
				],
			}]},
		}]},
		{"services": []},
	]}}]}}
}
