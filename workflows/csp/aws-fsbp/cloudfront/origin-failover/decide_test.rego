package policy.aws.cloudfront.origin_failover

import data.shisho
import future.keywords

test_origin_failover_configured_for_cloudfront_distributions if {
	# the origin failover is configured for all cloudfront distributions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"originGroups": [{
				"id": "test-origin-group-1",
				"members": [
					{"originId": "test-alb-2-797777777.ap-northeast-1.elb.amazonaws.com"},
					{"originId": "test-bucket-3.s3.ap-northeast-1.amazonaws.com"},
				],
			}],
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFBBBBBBB",
				"displayName": "E6M4TFBBBBBBB",
			},
			"originGroups": [{
				"id": "test-origin-group-2",
				"members": [
					{"originId": "test-alb-3-797777777.ap-northeast-1.elb.amazonaws.com"},
					{"originId": "test-bucket-4.s3.ap-northeast-1.amazonaws.com"},
				],
			}],
		},
	]}}]}}

	# the origin failover is not configured for all cloudfront distributions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"originGroups": [],
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFCCCCCCC",
				"displayName": "E6M4TFCCCCCCC",
			},
			"originGroups": [{
				"id": "test-origin-group-2",
				"members": [{"originId": "test-alb-2-797777777.ap-northeast-1.elb.amazonaws.com"}],
			}],
		},
	]}}]}}
}
