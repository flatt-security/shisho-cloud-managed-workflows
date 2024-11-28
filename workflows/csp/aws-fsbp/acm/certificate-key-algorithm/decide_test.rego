package policy.aws.acm.certificate_key_algorithm

import data.shisho
import future.keywords

test_whether_key_algorithm_for_acm_certificates_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"acm": {"certificates": [
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796aa",
				"displayName": "flatt-1.tech.test",
			},
			"keyAlgorithm": "RSA_2048",
		},
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796bb",
				"displayName": "flatt-2.tech.test",
			},
			"keyAlgorithm": "RSA_4096",
		},
	]}}]}}
}

test_whether_key_algorithm_for_acm_certificates_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"acm": {"certificates": [
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796aa",
				"displayName": "flatt-1.tech.test",
			},
			"keyAlgorithm": "RSA_1024",
		},
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796bb",
				"displayName": "flatt-2.tech.test",
			},
			"keyAlgorithm": "RSA_1024",
		},
	]}}]}}
}
