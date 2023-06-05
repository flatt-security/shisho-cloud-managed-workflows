package policy.aws.ecs.task

import data.shisho
import future.keywords

import data.shisho
import future.keywords

test_task_with_writeable_root_fs_container_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.ecs.container_fs_permission_kind
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|example-ecs-cluster|example-ecs-service"},
			"taskDefinition": {
				"arn": "arn:aws:ecs:ap-northeast-1:779392188153:task-definition/example-ecs-task-definition:1",
				"containerDefinitions": [
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": false,
					},
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": true,
					},
				],
			},
		}]},
	]}}]}}
}

test_task_with_readonly_root_fs_container_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.ecs.container_fs_permission_kind
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|example-ecs-cluster|example-ecs-service"},
			"taskDefinition": {
				"arn": "arn:aws:ecs:ap-northeast-1:779392188153:task-definition/example-ecs-task-definition:1",
				"containerDefinitions": [
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": true,
					},
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": true,
					},
				],
			},
		}]},
	]}}]}}
}

test_task_with_privileged_container_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.ecs.container_fs_permission_kind
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|example-ecs-cluster|example-ecs-service"},
			"taskDefinition": {
				"arn": "arn:aws:ecs:ap-northeast-1:779392188153:task-definition/example-ecs-task-definition:1",
				"containerDefinitions": [
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": true,
						"readonlyRootFilesystem": false,
					},
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": true,
					},
				],
			},
		}]},
	]}}]}}
}

test_task_with_privileged_container_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.ecs.container_privilege_kind
	]) == 1 with input as {"aws": {"accounts": [{"ecs": {"clusters": [
		{"services": []},
		{"services": [{
			"metadata": {"id": "aws-ecs-service|ap-northeast-1|example-ecs-cluster|example-ecs-service"},
			"taskDefinition": {
				"arn": "arn:aws:ecs:ap-northeast-1:779392188153:task-definition/example-ecs-task-definition:1",
				"containerDefinitions": [
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": false,
					},
					{
						"__typename": "AWSECSLinuxContainerDefinition",
						"name": "apache-helloworld",
						"privileged": false,
						"readonlyRootFilesystem": false,
					},
				],
			},
		}]},
	]}}]}}
}
