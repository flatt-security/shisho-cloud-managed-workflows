package policy.aws.guardduty.status

import data.shisho
import future.keywords

test_whether_status_of_guardduty_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"guardDuty": {"configurations": [{
				"region": r,
				"enabled": true,
			} |
				r := shisho.thirdparty.aws.regions[_]
			]},
		},
		{
			"metadata": {
				"id": "aws-account|779398888888",
				"displayName": "779398888888",
			},
			"guardDuty": {"configurations": [{
				"region": r,
				"enabled": true,
			} |
				r := shisho.thirdparty.aws.regions[_]
			]},
		},
	]}}
}

test_whether_status_of_guardduty_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"guardDuty": {"configurations": [
				{
					"region": "us-west-1",
					"enabled": false,
				},
				{
					"region": "us-east-2",
					"enabled": true,
				},
				{
					"region": "eu-central-1",
					"enabled": true,
				},
				{
					"region": "eu-west-1",
					"enabled": true,
				},
				{
					"region": "eu-west-2",
					"enabled": true,
				},
				{
					"region": "us-west-2",
					"enabled": true,
				},
				{
					"region": "ca-central-1",
					"enabled": true,
				},
				{
					"region": "us-east-1",
					"enabled": true,
				},
				{
					"region": "eu-west-3",
					"enabled": true,
				},
				{
					"region": "ap-northeast-2",
					"enabled": true,
				},
				{
					"region": "ap-southeast-1",
					"enabled": true,
				},
				{
					"region": "eu-north-1",
					"enabled": true,
				},
				{
					"region": "ap-southeast-2",
					"enabled": true,
				},
				{
					"region": "sa-east-1",
					"enabled": true,
				},
				{
					"region": "ap-northeast-1",
					"enabled": true,
				},
				{
					"region": "ap-south-1",
					"enabled": true,
				},
			]},
		},
		{
			"metadata": {
				"id": "aws-account|779398888888",
				"displayName": "779398888888",
			},
			"guardDuty": {"configurations": [
				{
					"region": "us-west-1",
					"enabled": false,
				},
				{
					"region": "us-east-2",
					"enabled": false,
				},
				{
					"region": "eu-central-1",
					"enabled": true,
				},
				{
					"region": "eu-west-1",
					"enabled": true,
				},
				{
					"region": "eu-west-2",
					"enabled": true,
				},
				{
					"region": "us-west-2",
					"enabled": true,
				},
				{
					"region": "ca-central-1",
					"enabled": true,
				},
				{
					"region": "us-east-1",
					"enabled": true,
				},
				{
					"region": "eu-west-3",
					"enabled": true,
				},
				{
					"region": "ap-northeast-2",
					"enabled": true,
				},
				{
					"region": "ap-southeast-1",
					"enabled": true,
				},
				{
					"region": "eu-north-1",
					"enabled": true,
				},
				{
					"region": "ap-southeast-2",
					"enabled": true,
				},
				{
					"region": "sa-east-1",
					"enabled": true,
				},
				{
					"region": "ap-northeast-1",
					"enabled": true,
				},
				{
					"region": "ap-south-1",
					"enabled": true,
				},
			]},
		},
	]}}
}
