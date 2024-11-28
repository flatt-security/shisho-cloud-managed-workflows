package policy.aws.ebs.volume_encryption

import data.shisho
import future.keywords

test_whether_volume_encryption_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee7777777",
				"displayName": "i-0d802faee7777777",
			},
			"blockDeviceMappings": [{"ebs": {"volume": {
				"id": "vol-0460d1495c7777777",
				"encrypted": true,
			}}}],
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee7777778",
				"displayName": "i-0d802faee7777778",
			},
			"blockDeviceMappings": [{"ebs": {"volume": {
				"id": "vol-0460d1495c7777778",
				"encrypted": true,
			}}}],
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee7777779",
				"displayName": "i-0d802faee7777779",
			},
			"blockDeviceMappings": [{"ebs": {"volume": {
				"id": "vol-0460d1495c7777779",
				"encrypted": true,
			}}}],
		},
	]}}]}}
}

test_whether_volume_encryption_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee7777777",
				"displayName": "i-0d802faee7777777",
			},
			"blockDeviceMappings": [{"ebs": {"volume": {
				"id": "vol-0460d1495c7777777",
				"encrypted": false,
			}}}],
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee7777778",
				"displayName": "i-0d802faee7777778",
			},
			"blockDeviceMappings": [{"ebs": {"volume": {
				"id": "vol-0460d1495c7777778",
				"encrypted": false,
			}}}],
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee7777779",
				"displayName": "i-0d802faee7777779",
			},
			"blockDeviceMappings": [{"ebs": {"volume": {
				"id": "vol-0460d1495c7777779",
				"encrypted": false,
			}}}],
		},
	]}}]}}
}
