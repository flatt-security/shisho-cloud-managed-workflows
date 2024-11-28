package policy.aws.ec2.instance_imdsv2

import data.shisho
import future.keywords

test_imdsv2_state_of_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"metadataOptions": {"httpTokens": "REQUIRED"},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"metadataOptions": {"httpTokens": "REQUIRED"},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"metadataOptions": {"httpTokens": "REQUIRED"},
		},
	]}}]}}
}

test_imdsv2_state_of_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"metadataOptions": {"httpTokens": "OPTIONAL"},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"metadataOptions": {"httpTokens": "OPTIONAL"},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"metadataOptions": {"httpTokens": "OPTIONAL"},
		},
	]}}]}}
}
