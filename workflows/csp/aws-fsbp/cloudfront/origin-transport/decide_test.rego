package policy.aws.cloudfront.origin_transport

import data.shisho
import future.keywords

test_origin_with_https_and_tls_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_version_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [
			{
				"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"backend": {
					"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
					"protocolPolicy": "HTTPS_ONLY",
					"sslProtocols": ["TLSV1_2"],
				},
			},
			{
				"id": "test-bucket.s3.ap-northeast-1.amazonaws.com",
				"domainName": "test-bucket.s3.ap-northeast-1.amazonaws.com",
				"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendS3Bucket"},
			},
		],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "ALLOW_ALL",
		},
		"cacheBehaviors": [],
	}]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [
			{
				"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"backend": {
					"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
					"protocolPolicy": "HTTPS_ONLY",
					"sslProtocols": ["TLSV1_2"],
				},
			},
			{
				"id": "test-bucket.s3.ap-northeast-1.amazonaws.com",
				"domainName": "test-bucket.s3.ap-northeast-1.amazonaws.com",
				"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendS3Bucket"},
			},
		],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "ALLOW_ALL",
		},
		"cacheBehaviors": [],
	}]}}]}}
}

test_origin_with_https_and_sslv3_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_version_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [
			{
				"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
				"backend": {
					"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
					"protocolPolicy": "HTTPS_ONLY",
					"sslProtocols": ["TLSV1_2", "SSLV3"],
				},
			},
			{
				"id": "test-bucket.s3.ap-northeast-1.amazonaws.com",
				"domainName": "test-bucket.s3.ap-northeast-1.amazonaws.com",
				"backend": {"__typename": "AWSCloudFrontDistributionOriginBackendS3Bucket"},
			},
		],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "ALLOW_ALL",
		},
		"cacheBehaviors": [],
	}]}}]}}
}

test_origin_with_http_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [{
			"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"backend": {
				"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
				"protocolPolicy": "HTTP_ONLY",
				"sslProtocols": [],
			},
		}],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "ALLOW_ALL",
		},
		"cacheBehaviors": [],
	}]}}]}}
}

test_origin_with_match_viewer_dependenet_protocol if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [{
			"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"backend": {
				"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
				"protocolPolicy": "MATCH_VIEWER",
				"sslProtocols": [],
			},
		}],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "ALLOW_ALL",
		},
		"cacheBehaviors": [],
	}]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [{
			"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"backend": {
				"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
				"protocolPolicy": "MATCH_VIEWER",
				"sslProtocols": [],
			},
		}],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "HTTPS_ONLY",
		},
		"cacheBehaviors": [],
	}]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.header.kind == shisho.decision.aws.cloudfront.origin_transport_kind
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6MAAAOSOK0BL"},
		"origins": [{
			"id": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"domainName": "test-alb-2-795120637.ap-northeast-1.elb.amazonaws.com",
			"backend": {
				"__typename": "AWSCloudFrontDistributionOriginBackendELBLoadBalancer",
				"protocolPolicy": "MATCH_VIEWER",
				"sslProtocols": [],
			},
		}],
		"defaultCacheBehavior": {
			"targetOriginId": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
			"viewerProtocolPolicy": "REDIRECT_TO_HTTPS",
		},
		"cacheBehaviors": [],
	}]}}]}}
}
