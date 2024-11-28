package policy.aws.cloudfront.waf

import data.shisho
import future.keywords

test_waf_configured_for_cloudfront_distributions if {
	# the WAF is configured for all cloudfront distributions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"webAclId": "arn:aws:wafv2:us-east-1:779397777777:global/webacl/CreatedByCloudFront-0412d9c5-c78b-4324-b89a-184747777777/61449942-167d-4a33-ba1c-17ac07777777",
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"webAclId": "473e64fd-f30b-4765-81a0-62ad96dd167a", # this is an ACL ID of WAF Classic
		},
	]}}]}}

	# the WAF is configured for all cloudfront distributions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"webAclId": "",
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"webAclId": "",
		},
	]}}]}}
}
