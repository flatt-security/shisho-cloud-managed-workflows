package policy.aws.cloudfront.root_object

import data.shisho
import future.keywords

test_empty_default_root_object_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26BBBQKUHTIWJ"},
			"config": {"defaultRootObject": null},
		},
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26AAAQKUHTIWJ"},
			"config": {"defaultRootObject": null},
		},
	]}}]}}
}

test_configured_default_root_object_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26BBBQKUHTIWJ"},
			"config": {"defaultRootObject": null},
		},
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26AAAQKUHTIWJ"},
			"config": {"defaultRootObject": "index.html"},
		},
	]}}]}}
}

test_tag_exception_works if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26BBBQKUHTIWJ"},
			"config": {"defaultRootObject": null},
			"tags": [{"key": "foo", "value": "bar=piyo"}],
		},
		{
			"metadata": {"id": "aws-cloudfront-distribution|E26AAAQKUHTIWJ"},
			"config": {"defaultRootObject": null},
			"tags": [{"key": "foo", "value": "unrelated"}],
		},
	]}}]}}
		with data.params as {"tag_exceptions": ["foo=bar=piyo"]}
}
