package policy.aws.cloudfront.default_certificate

import data.shisho
import future.keywords

test_default_certificate_is_not_used_for_cloudfront_distributions if {
	# the default certificate is not used for all cloudfront distributions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"viewerCertificate": {"cloudFrontDefaultCertificate": false},
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"viewerCertificate": {"cloudFrontDefaultCertificate": false},
		},
	]}}]}}

	# the default certificate is used for all cloudfront distributions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"viewerCertificate": {"cloudFrontDefaultCertificate": true},
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"viewerCertificate": {"cloudFrontDefaultCertificate": true},
		},
	]}}]}}
}
