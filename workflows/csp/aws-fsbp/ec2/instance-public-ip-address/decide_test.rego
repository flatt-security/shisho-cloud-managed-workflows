package policy.aws.ec2.instance_public_ip_address

import data.shisho
import future.keywords

test_public_accessibility_of_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"publicIpAddress": "",
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"publicIpAddress": "",
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"publicIpAddress": "",
		},
	]}}]}}
}

test_public_accessibility_of_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"publicIpAddress": "35.78.125.21",
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"publicIpAddress": "35.78.195.121",
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"publicIpAddress": "35.78.195.110",
		},
	]}}]}}
}
