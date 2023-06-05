package policy.aws.elb.alb_header

import data.shisho
import future.keywords

test_lb_dropping_invalid_header_fields_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.alb.invalid_header_handling_kind
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-700020007.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": true,
				"desyncMitigationMode": "DEFENSIVE",
			},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|example-alb"},
			"name": "example-alb",
			"dnsName": "example-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": true,
				"desyncMitigationMode": "DEFENSIVE",
			},
		},
	]}}]}}
}

test_lb_keeping_invalid_header_fields_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.alb.invalid_header_handling_kind
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-700020007.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": false,
				"desyncMitigationMode": "DEFENSIVE",
			},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|example-alb"},
			"name": "example-alb",
			"dnsName": "example-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": false,
				"desyncMitigationMode": "DEFENSIVE",
			},
		},
	]}}]}}
}

test_lb_with_desync_mitigation_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.alb.invalid_header_handling_kind
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-700020007.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": true,
				"desyncMitigationMode": "STRICTEST",
			},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|example-alb"},
			"name": "example-alb",
			"dnsName": "example-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": true,
				"desyncMitigationMode": "DEFENSIVE",
			},
		},
	]}}]}}
}

test_lb_without_desync_mitigation_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.alb.invalid_header_handling_kind
	]) == 2 with input as {"aws": {"accounts": [{"elb": {"loadBalancers": [
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|test-alb-2"},
			"name": "test-alb-2",
			"dnsName": "test-alb-2-700020007.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": true,
				"desyncMitigationMode": "MONITOR",
			},
		},
		{
			"metadata": {"id": "aws-elb-load-balancer|ap-northeast-1|application|example-alb"},
			"name": "example-alb",
			"dnsName": "example-alb-962304592.ap-northeast-1.elb.amazonaws.com",
			"attributes": {
				"dropInvalidHeaderFields": true,
				"desyncMitigationMode": "INVALID_VALUE",
			},
		},
	]}}]}}
}
