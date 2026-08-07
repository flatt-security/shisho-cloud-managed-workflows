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

test_environment_variable_names_appear_once_per_container if {
	ds := [d | decisions[d]] with input as {"aws": {"accounts": [{"ecs": {"clusters": [{"services": [{
		"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-1"},
		"taskDefinition": {"containerDefinitions": [
			{
				"name": "simple-app",
				"environment": [
					{"name": "TEST_ENV1"},
					{"name": "TEST_ENV2"},
					{"name": "TEST_ENV3"},
				],
			},
			{
				"name": "busybox",
				"environment": [{"name": "TEST_ENV9"}],
			},
		]},
	}]}]}}]}}

	count(ds) == 1
	json.unmarshal(ds[0].payload).containers == [
		{"name": "simple-app", "environment_variables": ["TEST_ENV1", "TEST_ENV2", "TEST_ENV3"]},
		{"name": "busybox", "environment_variables": ["TEST_ENV9"]},
	]
}

test_denied_decision_lists_each_environment_variable_once if {
	ds := [d | decisions[d]] with input as {"aws": {"accounts": [{"ecs": {"clusters": [{"services": [{
		"metadata": {"id": "aws-ecs-service|ap-northeast-1|ecs-test-1|ecs-test-service-2"},
		"taskDefinition": {"containerDefinitions": [{
			"name": "simple-app",
			"environment": [
				{"name": "AWS_ACCESS_KEY_ID"},
				{"name": "TEST_ENV1"},
			],
		}]},
	}]}]}}]}}

	count(ds) == 1
	not shisho.decision.is_allowed(ds[0])
	json.unmarshal(ds[0].payload).containers == [{
		"name": "simple-app",
		"environment_variables": ["AWS_ACCESS_KEY_ID", "TEST_ENV1"],
	}]
}
