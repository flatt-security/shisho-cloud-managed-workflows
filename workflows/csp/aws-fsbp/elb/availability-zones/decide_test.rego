package policy.aws.elb.availability_zones

import data.shisho
import future.keywords

test_lb_with_availability_zones_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"__typename": "AWSELBNetworkLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|network|test-nlb-8",
				"displayName": "test-nlb-8",
			},
			"nlbAvailabilityZones": [
				{"name": "ap-northeast-1c"},
				{"name": "ap-northeast-1d"},
				{"name": "ap-northeast-1a"},
			],
		},
		{
			"__typename": "AWSELBApplicationLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|application|h4b-ecs-alb",
				"displayName": "h4b-ecs-alb",
			},
			"albAvailabilityZones": [
				{"name": "ap-northeast-1c"},
				{"name": "ap-northeast-1a"},
			],
		},
		{
			"__typename": "AWSELBApplicationLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|application|test-alb-9",
				"displayName": "test-alb-9",
			},
			"albAvailabilityZones": [
				{"name": "ap-northeast-1d"},
				{"name": "ap-northeast-1c"},
				{"name": "ap-northeast-1a"},
			],
		},
		{
			"__typename": "AWSELBGatewayLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|gateway|test-glb-7",
				"displayName": "test-glb-7",
			},
			"glbAvailabilityZones": [
				{"name": "ap-northeast-1c"},
				{"name": "ap-northeast-1d"},
				{"name": "ap-northeast-1a"},
			],
		},
		{
			"__typename": "AWSELBClassicLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|classic|test-nlb-8",
				"displayName": "test-nlb-8",
			},
			"clbAvailabilityZones": ["ap-northeast-1c"],
		},
	]}}]}}
}

test_lb_with_availability_zones_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"__typename": "AWSELBNetworkLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|network|test-nlb-8",
				"displayName": "test-nlb-8",
			},
			"nlbAvailabilityZones": [{"name": "ap-northeast-1c"}],
		},
		{
			"__typename": "AWSELBApplicationLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|application|h4b-ecs-alb",
				"displayName": "h4b-ecs-alb",
			},
			"albAvailabilityZones": [{"name": "ap-northeast-1c"}],
		},
		{
			"__typename": "AWSELBApplicationLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|application|test-alb-9",
				"displayName": "test-alb-9",
			},
			"albAvailabilityZones": [{"name": "ap-northeast-1a"}],
		},
		{
			"__typename": "AWSELBGatewayLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|gateway|test-glb-7",
				"displayName": "test-glb-7",
			},
			"glbAvailabilityZones": [{"name": "ap-northeast-1c"}],
		},
		{
			"__typename": "AWSELBClassicLoadBalancer",
			"metadata": {
				"id": "aws-elb|ap-northeast-1|classic|test-nlb-8",
				"displayName": "test-nlb-8",
			},
			"clbAvailabilityZones": ["ap-northeast-1c"],
		},
	]}}]}}
}
