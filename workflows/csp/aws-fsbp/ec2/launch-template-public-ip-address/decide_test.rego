package policy.aws.ec2.launch_template_public_ip_address

import data.shisho
import future.keywords

test_whether_public_accessibility_of_launch_templates_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"ec2": {"launchTemplates": [
		{
			"metadata": {
				"id": "aws-ec2-launch-template|ap-northeast-1|lt-0d414d1fdd534faab",
				"displayName": "lt-0d414d1fdd534faab",
			},
			"defaultVersion": {
				"number": 7,
				"details": {"networkInterfaces": [
					{
						"networkInterface": null,
						"associatePublicIpAddress": false,
					},
					{
						"networkInterface": {
							"id": "eni-0b39b803a7b307e8d",
							"association": {"publicIp": ""},
						},
						"associatePublicIpAddress": false,
					},
				]},
			},
		},
		{
			"metadata": {
				"id": "aws-ec2-launch-template|ap-northeast-1|lt-0d414d1fdd534fabc",
				"displayName": "lt-0d414d1fdd534fabc",
			},
			"defaultVersion": {
				"number": 2,
				"details": {"networkInterfaces": [
					{
						"networkInterface": null,
						"associatePublicIpAddress": false,
					},
					{
						"networkInterface": {
							"id": "eni-0b39b803a7b307e9f",
							"association": null,
						},
						"associatePublicIpAddress": false,
					},
				]},
			},
		},
		{
			"metadata": {
				"id": "aws-ec2-launch-template|ap-northeast-1|lt-0d414d1fdd534face",
				"displayName": "lt-0d414d1fdd534face",
			},
			"defaultVersion": {
				"number": 2,
				"details": {"networkInterfaces": [
					{
						"networkInterface": null,
						"associatePublicIpAddress": false,
					},
					{
						"networkInterface": {
							"id": "eni-0b39b803a7b307e1f",
							"association": null,
						},
						"associatePublicIpAddress": false,
					},
				]},
			},
		},
	]}}]}}
}

test_whether_public_accessibility_of_launch_templates_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"launchTemplates": [
		{
			"metadata": {
				"id": "aws-ec2-launch-template|ap-northeast-1|lt-0d414d1fdd534faab",
				"displayName": "lt-0d414d1fdd534faab",
			},
			"defaultVersion": {
				"number": 7,
				"details": {"networkInterfaces": [
					{
						"networkInterface": null,
						"associatePublicIpAddress": false,
					},
					{
						"networkInterface": {
							"id": "eni-0b39b803a7b307e8d",
							"association": {"publicIp": "52.194.82.187"},
						},
						"associatePublicIpAddress": false,
					},
				]},
			},
		},
		{
			"metadata": {
				"id": "aws-ec2-launch-template|ap-northeast-1|lt-0d414d1fdd534fabc",
				"displayName": "lt-0d414d1fdd534fabc",
			},
			"defaultVersion": {
				"number": 2,
				"details": {"networkInterfaces": [
					{
						"networkInterface": null,
						"associatePublicIpAddress": true,
					},
					{
						"networkInterface": {
							"id": "eni-0b39b803a7b307e9f",
							"association": null,
						},
						"associatePublicIpAddress": false,
					},
				]},
			},
		},
	]}}]}}
}
