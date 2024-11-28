package policy.aws.cloudtrail.usage

import data.shisho
import future.keywords

test_whether_cloudtrail_is_ready_to_track_logs_in_all_regions if {
	# check if the CloudTrail is ready to track logs in all regions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779392177777",
				"displayName": "779392177777",
			},
			"cloudTrail": {"trails": [
				{
					"arn": "tbd",
					"isMultiRegionTrail": false,
					"status": {"isLogging": true},
					"eventSelectors": [{
						"includeManagementEvents": true,
						"readWriteType": "ALL",
					}],
				},
				{
					"arn": "tbd",
					"isMultiRegionTrail": true,
					"status": {"isLogging": true},
					"eventSelectors": [{
						"includeManagementEvents": true,
						"readWriteType": "ALL",
					}],
				},
			]},
		},
		{
			"metadata": {
				"id": "aws-account|779392188888",
				"displayName": "779392188888",
			},
			"cloudTrail": {"trails": [{
				"arn": "tbd",
				"isMultiRegionTrail": true,
				"status": {"isLogging": true},
				"eventSelectors": [{
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
		},
	]}}

	# check if the CloudTrail is not ready to track logs in all regions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779392177777",
				"displayName": "779392177777",
			},
			"cloudTrail": {"trails": [
				{
					"arn": "tbd",
					"isMultiRegionTrail": false,
					"status": {"isLogging": false},
					"eventSelectors": [{
						"includeManagementEvents": false,
						"readWriteType": "ALL",
					}],
				},
				{
					"arn": "tbd",
					"isMultiRegionTrail": false,
					"status": {"isLogging": true},
					"eventSelectors": [{
						"includeManagementEvents": true,
						"readWriteType": "ALL",
					}],
				},
			]},
		},
		{
			"metadata": {
				"id": "aws-account|779392188888",
				"displayName": "779392188888",
			},
			"cloudTrail": {"trails": [{
				"arn": "tbd",
				"isMultiRegionTrail": true,
				"status": {"isLogging": false},
				"eventSelectors": [{
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779392199999",
				"displayName": "779392199999",
			},
			"cloudTrail": {"trails": [{
				"arn": "tbd",
				"isMultiRegionTrail": true,
				"status": {"isLogging": true},
				"eventSelectors": [{
					"includeManagementEvents": false,
					"readWriteType": "ALL",
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779392100000",
				"displayName": "779392100000",
			},
			"cloudTrail": {"trails": [{
				"arn": "tbd",
				"isMultiRegionTrail": true,
				"status": {"isLogging": true},
				"eventSelectors": [{
					"includeManagementEvents": true,
					"readWriteType": "READ_ONLY",
				}],
			}]},
		},
	]}}
}
