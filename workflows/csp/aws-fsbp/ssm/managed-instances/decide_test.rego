package policy.aws.ssm.managed_instances

import data.shisho
import future.keywords

test_whether_ssm_managed_instances_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-04312cf26e96f73aa",
				"displayName": "i-04312cf26e96f73aa",
			},
			"state": {"state": "RUNNING"},
			"ssmConfiguration": {"associationStatus": "Success"},
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-2|i-02ddba3ac624042bb",
				"displayName": "i-02ddba3ac624042bb",
			},
			"state": {"state": "STOPPED"},
			"ssmConfiguration": {"associationStatus": "Success"},
		},
	]}}]}}
}

test_whether_ssm_managed_instances_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.has_severity(d, shisho.decision.severity_medium)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-008467a2d2438afaa",
				"displayName": "i-008467a2d2438afaa",
			},
			"state": {"state": "RUNNING"},
			"ssmConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-062545756514177bb",
				"displayName": "i-062545756514177bb",
			},
			"state": {"state": "RUNNING"},
			"ssmConfiguration": null,
		},
	]}}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.has_severity(d, shisho.decision.severity_low)
	]) == 2 with input as {"aws": {"accounts": [{"ec2": {"instances": [
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-008467a2d2438afaa",
				"displayName": "i-008467a2d2438afaa",
			},
			"state": {"state": "STOPPED"},
			"ssmConfiguration": null,
		},
		{
			"metadata": {
				"id": "aws-ec2-instance|ap-northeast-1|i-062545756514177bb",
				"displayName": "i-062545756514177bb",
			},
			"state": {"state": "PENDING"},
			"ssmConfiguration": null,
		},
	]}}]}}
}
