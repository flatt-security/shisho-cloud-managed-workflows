package policy.aws.ec2.instance_vpc_endpoint

import data.shisho
import future.keywords

test_unused_duration_of_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"vpc": {
				"id": "vpc-0fb9667dee2b36e00",
				"endpoints": [{
					"id": "vpce-01c9868552e567b24",
					"serviceName": "com.amazonaws.ap-northeast-1.ec2",
				}],
			},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0633259a9098f15a8",
				"displayName": "i-0633259a9098f15a8",
			},
			"vpc": {
				"id": "vpc-0fb9667dee2b36e00",
				"endpoints": [{
					"id": "vpce-01c9868552e567b24",
					"serviceName": "com.amazonaws.ap-northeast-1.ec2",
				}],
			},
		},
	]}}]}}
}

test_unused_duration_of_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-0d802faee271125a0",
				"displayName": "i-0d802faee271125a0",
			},
			"vpc": {
				"id": "vpc-0fb9667dee2b36e00",
				"endpoints": [{
					"id": "vpce-01c9868552e567b24",
					"serviceName": "com.amazonaws.ap-northeast-1.s3",
				}],
			},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-060ae6275084f81f5",
				"displayName": "i-060ae6275084f81f5",
			},
			"vpc": {
				"id": "vpc-06dc8a2abafdfd031",
				"endpoints": [],
			},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac6240423d",
				"displayName": "i-02ddba3ac6240423d",
			},
			"vpc": {
				"id": "vpc-0f31afb45624b35c7",
				"endpoints": [],
			},
		},
	]}}]}}
}
