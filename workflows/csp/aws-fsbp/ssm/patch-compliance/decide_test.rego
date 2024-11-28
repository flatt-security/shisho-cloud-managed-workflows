package policy.aws.ssm.patch_compliance

import data.shisho
import future.keywords

test_whether_patch_compliance_for_ssm_managed_instances_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ssm": {"managedInstances": [
		{
			"metadata": {
				"id": "aws-ssm-managed-instance|ap-northeast-1|i-04312cf26e96f73aa",
				"displayName": "i-04312cf26e96f73aa",
			},
			"compliances": [
				{
					"id": "apr.x86_64",
					"title": "apr.x86_64:0:1.7.2-1.amzn2",
					"status": "COMPLIANT",
				},
				{
					"id": "bind-export-libs.x86_64",
					"title": "bind-export-libs.x86_64:32:9.11.4-26.P2.amzn2.13.1",
					"status": "COMPLIANT",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-ssm-managed-instance|ap-northeast-1|i-05eac82a012dbd1bb",
				"displayName": "i-05eac82a012dbd1bb",
			},
			"compliances": [],
		},
	]}}]}}
}

test_whether_patch_compliance_for_ssm_managed_instances_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ssm": {"managedInstances": [
		{
			"metadata": {
				"id": "aws-ssm-managed-instance|ap-northeast-1|i-04312cf26e96f73aa",
				"displayName": "i-04312cf26e96f73aa",
			},
			"compliances": [
				{
					"id": "apr.x86_64",
					"title": "apr.x86_64:0:1.7.2-1.amzn2",
					"status": "NON_COMPLIANT",
				},
				{
					"id": "bind-export-libs.x86_64",
					"title": "bind-export-libs.x86_64:32:9.11.4-26.P2.amzn2.13.1",
					"status": "NON_COMPLIANT",
				},
			],
		},
		{
			"metadata": {
				"id": "aws-ssm-managed-instance|ap-northeast-1|i-05eac82a012dbd1bb",
				"displayName": "i-05eac82a012dbd1bb",
			},
			"compliances": [
				{
					"id": "glibc-minimal-langpack.x86_64",
					"title": "glibc-minimal-langpack.x86_64:0:2.26-63.amzn2",
					"status": "NON_COMPLIANT",
				},
				{
					"id": "glibc-static.x86_64",
					"title": "glibc-static.x86_64:0:2.26-63.amzn2",
					"status": "COMPLIANT",
				},
			],
		},
	]}}]}}
}
