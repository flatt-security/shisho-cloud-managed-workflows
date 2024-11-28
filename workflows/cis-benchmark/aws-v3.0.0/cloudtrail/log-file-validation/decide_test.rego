package policy.aws.cloudtrail.log_file_validation

import data.shisho
import future.keywords

test_whether_log_validation_for_cloudtrail_is_enabled if {
	# check if the log validation for CloudTrail is enabled
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"logFileValidationEnabled": true,
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"logFileValidationEnabled": true,
		},
	]}}]}}

	# check if the log validation for CloudTrail is not enabled
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"logFileValidationEnabled": false,
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"logFileValidationEnabled": false,
		},
	]}}]}}
}
