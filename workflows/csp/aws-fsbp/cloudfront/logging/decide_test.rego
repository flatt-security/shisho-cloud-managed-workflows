package policy.aws.cloudfront.logging

import data.shisho
import future.keywords

test_buckets_with_logging_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": {"bucketId": "test-shisho-bucket-3.s3.amazonaws.com"}},
	}]}}]}}
}

test_buckets_with_no_logging_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
			"config": {"logging": null},
		},
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26UGWQKUHTIWJ"},
			"config": {"logging": null},
		},
	]}}]}}
}

test_tag_exception_works if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
			"config": {"logging": null},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26UGWQKUHTIWJ"},
			"config": {"logging": null},
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
