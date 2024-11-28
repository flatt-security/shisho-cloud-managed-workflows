package policy.aws.ec2.instance_virtualization

import data.shisho
import future.keywords

test_whether_virtualization_of_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"virtualizationType": "HVM",
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"virtualizationType": "HVM",
		},
	]}}]}}
}

test_whether_virtualization_of_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"virtualizationType": "PARAVIRTUAL",
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"virtualizationType": "PARAVIRTUAL",
		},
	]}}]}}
}
