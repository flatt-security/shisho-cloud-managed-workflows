package policy.aws.cloudfront.sni

import data.shisho
import future.keywords

test_sni_is_used_for_cloudfront_distributions if {
	# the SNI is used for all cloudfront distributions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"viewerCertificate": {
				"cloudFrontDefaultCertificate": false,
				"sslSupportMethod": "SNI_ONLY",
			},
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"viewerCertificate": {
				"cloudFrontDefaultCertificate": false,
				"sslSupportMethod": "SNI_ONLY",
			},
		},
	]}}]}}

	# the SNI is used for all cloudfront distributions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudFront": {"distributions": [
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E6M4TFAAAAAAA",
				"displayName": "E6M4TFAAAAAAA",
			},
			"viewerCertificate": {
				"cloudFrontDefaultCertificate": false,
				"sslSupportMethod": "VIP",
			},
		},
		{
			"metadata": {
				"id": "aws-cloudfront-distribution|E26UGWQBBBBBBB",
				"displayName": "E26UGWQBBBBBBB",
			},
			"viewerCertificate": {
				"cloudFrontDefaultCertificate": true,
				"sslSupportMethod": "SNI_ONLY",
			},
		},
	]}}]}}
}
