package policy.aws.elb.logging

import data.shisho
import future.keywords

test_lb_with_log_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"accessLog": {
				"enabled": true,
				"s3BucketName": "foo",
				"s3BucketPrefix": "",
			}},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|h4b-ecs-alb"},
			"name": "h4b-ecs-alb",
			"dnsName": "h4b-ecs-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"accessLog": {
				"enabled": true,
				"s3BucketName": "foo",
				"s3BucketPrefix": "",
			}},
		},
	]}}]}}
}

test_lb_without_log_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"accessLog": {
				"enabled": false,
				"s3BucketName": null,
				"s3BucketPrefix": null,
			}},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|h4b-ecs-alb"},
			"name": "h4b-ecs-alb",
			"dnsName": "h4b-ecs-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {"accessLog": {
				"enabled": false,
				"s3BucketName": null,
				"s3BucketPrefix": null,
			}},
		},
	]}}]}}
}
