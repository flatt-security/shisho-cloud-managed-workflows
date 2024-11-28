package policy.aws.networking.subnet_public_ip

import data.shisho
import future.keywords

test_whether_public_ip_allocation_of_subnets_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-2|vpc-0f31afb45624b35c7",
				"displayName": "vpc-0f31afb45624b35c7",
			},
			"subnets": [
				{
					"id": "subnet-02c79a018e59e4f8f",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0af023cd2c436082f",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0cd35ac6af0cd0e3a",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0dfe2f606ad995ccf",
					"mapPublicIpOnLaunch": false,
				},
			],
		},
		{
			"metadata": {
				"id": "aws-vpc|us-west-1|vpc-0c7dd99f9cf0199b0",
				"displayName": "vpc-0c7dd99f9cf0199b0",
			},
			"subnets": [
				{
					"id": "subnet-036e70dce60405207",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0d91f92e0b34a1508",
					"mapPublicIpOnLaunch": false,
				},
			],
		},
	]}}]}}
}

test_whether_public_ip_allocation_of_subnets_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-2|vpc-0f31afb45624b35c7",
				"displayName": "vpc-0f31afb45624b35c7",
			},
			"subnets": [
				{
					"id": "subnet-02c79a018e59e4f8f",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0af023cd2c436082f",
					"mapPublicIpOnLaunch": true,
				},
				{
					"id": "subnet-0cd35ac6af0cd0e3a",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0dfe2f606ad995ccf",
					"mapPublicIpOnLaunch": false,
				},
			],
		},
		{
			"metadata": {
				"id": "aws-vpc|us-west-1|vpc-0c7dd99f9cf0199b0",
				"displayName": "vpc-0c7dd99f9cf0199b0",
			},
			"subnets": [
				{
					"id": "subnet-036e70dce60405207",
					"mapPublicIpOnLaunch": false,
				},
				{
					"id": "subnet-0d91f92e0b34a1508",
					"mapPublicIpOnLaunch": true,
				},
			],
		},
	]}}]}}
}
