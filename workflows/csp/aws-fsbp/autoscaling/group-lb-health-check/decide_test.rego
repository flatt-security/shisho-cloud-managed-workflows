package policy.aws.autoscaling.group_lb_health_check

import data.shisho
import future.keywords

test_whether_health_check_for_autoscaling_groups_with_clb_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"loadBalancer": {"classicLoadBalancers": [{"name": "test-classic-elb-5"}]},
			"healthCheckType": "ELB",
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"loadBalancer": {"classicLoadBalancers": [{"name": "test-classic-elb-6"}]},
			"healthCheckType": "ELB",
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-3",
				"displayName": "test-group-3",
			},
			"loadBalancer": {"classicLoadBalancers": [{"name": "test-classic-elb-7"}]},
			"healthCheckType": "ELB",
		},
	]}}]}}
}

test_whether_health_check_for_autoscaling_groups_with_clb_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"autoScaling": {"groups": [
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-1",
				"displayName": "test-group-1",
			},
			"loadBalancer": {"classicLoadBalancers": [{"name": "test-classic-elb-5"}]},
			"healthCheckType": "EC2",
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-2",
				"displayName": "test-group-2",
			},
			"loadBalancer": {"classicLoadBalancers": [{"name": "test-classic-elb-6"}]},
			"healthCheckType": "VPC_LATTICE",
		},
		{
			"metadata": {
				"id": "aws-auto-scaling-group|ap-northeast-1|test-group-3",
				"displayName": "test-group-3",
			},
			"loadBalancer": {"classicLoadBalancers": [{"name": "test-classic-elb-7"}]},
			"healthCheckType": "VPC_LATTICE",
		},
	]}}]}}
}
