package policy.aws.ssm.association_compliance

import data.shisho
import future.keywords

test_whether_association_compliance_for_ssm_managed_instances_is_allowed if {
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
					"id": "b8d21add-17af-4168-8c4f-84189c4c9338",
					"title": "AWS-AmazonLinux2DefaultPatchBaseline",
					"status": "COMPLIANT",
				},
				{
					"id": "9550c059-9770-452d-a4ab-64d27bf66d22",
					"title": "",
					"status": "COMPLIANT",
				},
				{
					"id": "c349cd00-90f0-48b9-a6ae-0cb0666ef16d",
					"title": "",
					"status": "COMPLIANT",
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
					"id": "b8d21add-17af-4168-8c4f-84189c4c9338",
					"title": "AWS-AmazonLinux2023DefaultPatchBaseline",
					"status": "COMPLIANT",
				},
				{
					"id": "c6db08b4-11f5-4527-9bd2-255a43c876d3",
					"title": "",
					"status": "COMPLIANT",
				},
			],
		},
	]}}]}}
}

test_whether_association_compliance_for_ssm_managed_instances_is_denied if {
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
					"id": "b8d21add-17af-4168-8c4f-84189c4c9338",
					"title": "AWS-AmazonLinux2DefaultPatchBaseline",
					"status": "NON_COMPLIANT",
				},
				{
					"id": "c6db08b4-11f5-4527-9bd2-255a43c876d3",
					"title": "",
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
					"id": "b8d21add-17af-4168-8c4f-84189c4c9338",
					"title": "AWS-AmazonLinux2023DefaultPatchBaseline",
					"status": "NON_COMPLIANT",
				},
				{
					"id": "c6db08b4-11f5-4527-9bd2-255a43c876d3",
					"title": "",
					"status": "NON_COMPLIANT",
				},
			],
		},
	]}}]}}
}
