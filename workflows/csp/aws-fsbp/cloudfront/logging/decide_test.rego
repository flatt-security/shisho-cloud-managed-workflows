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

test_distributions_with_standard_logging_v2_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": null, "standardLoggingV2": {"enabled": true}},
	}]}}]}}
}

test_distributions_with_disabled_standard_logging_v2_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": null, "standardLoggingV2": {"enabled": false}},
	}]}}]}}
}

test_distributions_with_unretrievable_standard_logging_v2_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": null, "standardLoggingV2": null},
	}]}}]}}
}

test_distributions_with_a_bucket_and_standard_logging_v2_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.payload == "{\"bucket_id\":\"test-shisho-bucket-3.s3.amazonaws.com\"}"
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": {"bucketId": "test-shisho-bucket-3.s3.amazonaws.com"}, "standardLoggingV2": {"enabled": true}},
	}]}}]}}
}

test_distributions_allowed_by_standard_logging_v2_alone_report_an_empty_bucket_id if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
		d.payload == "{\"bucket_id\":\"\"}"
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": null, "standardLoggingV2": {"enabled": true}},
	}]}}]}}
}

# A snapshot taken before the standard logging (v2) field existed carries no such
# field at all, which is distinct from the field being present and null.
test_distributions_without_the_standard_logging_v2_field_are_evaluated_on_the_bucket_alone if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": null},
	}]}}]}}

	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E26UGWQKUHTIWJ"},
		"config": {"logging": {"bucketId": "test-shisho-bucket-3.s3.amazonaws.com"}},
	}]}}]}}
}

test_distributions_with_a_standard_logging_v2_without_enabled_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": null, "standardLoggingV2": {}},
	}]}}]}}
}

test_distributions_with_an_empty_bucket_id_fall_back_to_standard_logging_v2 if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [{
		"metadata": {"id": "aws-cloudfront-distribution|E6M4TFOSOK0BL"},
		"config": {"logging": {"bucketId": ""}, "standardLoggingV2": {"enabled": true}},
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
