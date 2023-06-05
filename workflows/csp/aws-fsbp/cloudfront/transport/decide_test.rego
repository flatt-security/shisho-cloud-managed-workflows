package policy.aws.cloudfront.transport

import data.shisho
import future.keywords

test_permissive_protocol_policy_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|EAA4TFOSOK0BL"},
		"defaultCacheBehavior": {
			"targetOriginId": "test-bucket.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "ALLOW_ALL",
		},
		"cacheBehaviors": [],
	}]}}]}}
}

test_strict_protocol_policy_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|EAA4TFOSOK0BL"},
		"defaultCacheBehavior": {
			"targetOriginId": "test-bucket.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "HTTPS_ONLY",
		},
		"cacheBehaviors": [],
	}]}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|EAA4TFOSOK0BL"},
		"defaultCacheBehavior": {
			"targetOriginId": "test-bucket.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "REDIRECT_TO_HTTPS",
		},
		"cacheBehaviors": [],
	}]}}]}}
}
