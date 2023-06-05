package policy.aws.elb.deletion_protection

import data.shisho
import future.keywords

test_lb_with_protection_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"enabledDeletionProtection": true},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|h4b-ecs-alb"},
			"name": "h4b-ecs-alb",
			"dnsName": "h4b-ecs-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"enabledDeletionProtection": true},
		},
	]}}]}}
}

test_lb_without_protection_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"enabledDeletionProtection": false},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|h4b-ecs-alb"},
			"name": "h4b-ecs-alb",
			"dnsName": "h4b-ecs-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"enabledDeletionProtection": false},
		},
	]}}]}}
}
