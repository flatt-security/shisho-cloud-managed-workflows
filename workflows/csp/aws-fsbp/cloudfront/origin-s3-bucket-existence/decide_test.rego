package policy.aws.cloudfront.origin_s3_bucket_existence

import data.shisho
import future.keywords

test_s3_origins_point_existent_buckets_cloudfront_distributions if {
	# the S3 origins point to existent buckets for all cloudfront distributions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"origins": [
				{
					"domainName": "test-shisho-bucket-1.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": {"metadata": {
						"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-1",
						"displayName": "test-shisho-bucket-1",
					}}},
				},
				{
					"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": {"metadata": {
						"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-3",
						"displayName": "test-shisho-bucket-3",
					}}},
				},
			],
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"origins": [
				{
					"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": {"metadata": {
						"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-3",
						"displayName": "test-shisho-bucket-3",
					}}},
				},
				{
					"domainName": "test-shisho-bucket-4.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": {"metadata": {
						"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-4",
						"displayName": "test-shisho-bucket-4",
					}}},
				},
			],
		},
	]}}]}}

	# the S3 origins point to existent buckets for all cloudfront distributions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"origins": [
				{
					"domainName": "test-shisho-bucket-4.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": null},
				},
				{
					"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": {"metadata": {
						"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-3",
						"displayName": "test-shisho-bucket-3",
					}}},
				},
			],
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"origins": [
				{
					"domainName": "test-shisho-bucket-3.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": {"metadata": {
						"id": "aws-s3-bucket|ap-northeast-1|test-shisho-bucket-3",
						"displayName": "test-shisho-bucket-3",
					}}},
				},
				{
					"domainName": "test-shisho-bucket-4.s3.ap-northeast-1.amazonaws.com",
					"backend": {"bucket": null},
				},
			],
		},
	]}}]}}
}
