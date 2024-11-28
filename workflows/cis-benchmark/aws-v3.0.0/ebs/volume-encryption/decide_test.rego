package policy.aws.ebs.volume_encryption

import data.shisho
import future.keywords

test_whether_default_encryption_is_enabled_for_aws_ebs if {
	# check if the default encryption is enabled for AWS EBS volumes
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"ec2": {"defaultEbsEncryptions": [
				{
					"region": "AP_NORTHEAST_1",
					"enabled": true,
				},
				{
					"region": "AP_NORTHEAST_2",
					"enabled": true,
				},
			]},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"ec2": {"defaultEbsEncryptions": [
				{
					"region": "AP_NORTHEAST_1",
					"enabled": true,
				},
				{
					"region": "AP_NORTHEAST_2",
					"enabled": true,
				},
			]},
		},
	]}}

	# check if the default encryption is disabled for AWS EBS volumes
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"ec2": {"defaultEbsEncryptions": [
				{
					"region": "AP_NORTHEAST_1",
					"enabled": true,
				},
				{
					"region": "AP_NORTHEAST_2",
					"enabled": false,
				},
			]},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"ec2": {"defaultEbsEncryptions": [
				{
					"region": "AP_NORTHEAST_1",
					"enabled": false,
				},
				{
					"region": "AP_NORTHEAST_2",
					"enabled": false,
				},
			]},
		},
	]}}
}
