package policy.aws.cloudfront.origin_access

import data.shisho
import future.keywords

test_bucket_origins_with_oac_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"origins": [
			{
				"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"accessControlId": null,
				"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer"},
			},
			{
				"id": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
				"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
				"accessControlId": "E2TIFT9NC4DMRF",
				"backend": {
					"__typename": "AWSCloudFrontDistributionOriginBackendS3Bucket",
					"accessIdentityId": null,
				},
			},
		],
	}]}}]}}
}

test_bucket_origins_no_iam_guard_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		not shisho.decision.has_severity(d, shisho.decision.severity_low)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"origins": [
			{
				"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"accessControlId": null,
				"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer"},
			},
			{
				"id": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
				"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
				"accessControlId": null,
				"backend": {
					"__typename": "AWSCloudFrontDistributionOriginBackendS3Bucket",
					"accessIdentityId": null,
				},
			},
		],
	}]}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.has_severity(d, shisho.decision.severity_low)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"origins": [
			{
				"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"accessControlId": null,
				"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer"},
			},
			{
				"id": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
				"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
				"accessControlId": null,
				"backend": {
					"__typename": "AWSCloudFrontDistributionOriginBackendS3Bucket",
					"accessIdentityId": "this-value-is-set",
				},
			},
		],
	}]}}]}}
}

test_no_s3_origins_will_be_denied if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"origins": [{
			"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"accessControlId": null,
			"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer"},
		}],
	}]}}]}}
}
