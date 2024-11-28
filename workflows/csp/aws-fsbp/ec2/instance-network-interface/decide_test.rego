package policy.aws.ec2.instance_network_interface

import data.shisho
import future.keywords

test_whether_network_interface_of_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"networkInterfaces": [{"id": "eni-0a6a4ace5dba85f16"}],
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"networkInterfaces": [{"id": "eni-026c811f7231fdb77"}],
		},
	]}}]}}
}

test_whether_network_interface_of_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"networkInterfaces": [
				{"id": "eni-0a6a4ace5dba85f16"},
				{"id": "eni-0a6a4ace5dba85f17"},
			],
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"networkInterfaces": [],
		},
	]}}]}}
}
