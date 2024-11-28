package policy.aws.s3.bucket_read_trail

import data.shisho
import future.keywords

test_whether_cloudtrail_logs_read_data_events_of_s3_buckets if {
	# check if the CloudTrail logs read data events of S3 buckets
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"metadata": {
			"id": "aws-account|779392177777",
			"displayName": "779392177777",
		},
		"cloudTrail": {"trails": [
			{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
					"displayName": "test-trail-1",
				},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"dataResources": [{
						"type": "AWS::S3::Object",
						"values": ["arn:aws:s3"],
					}],
					"readWriteType": "READ_ONLY",
				}],
			},
			{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-3",
					"displayName": "test-trail-3",
				},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"dataResources": [{
						"type": "AWS::S3::Object",
						"values": ["arn:aws:s3"],
					}],
					"readWriteType": "ALL",
				}],
			},
			{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
					"displayName": "test-trail-2",
				},
				"eventSelectors": [
					{
						"__typename": "AWSCloudTrailAdvancedEventSelector",
						"name": "",
						"fieldSelectors": [
							{
								"field": "eventCategory",
								"endsWith": [],
								"equals": ["Data"],
								"notEndsWith": [],
								"notEquals": [],
								"notStartsWith": [],
								"startsWith": [],
							},
							{
								"field": "resources.type",
								"endsWith": [],
								"equals": ["AWS::S3::Object"],
								"notEndsWith": [],
								"notEquals": [],
								"notStartsWith": [],
								"startsWith": [],
							},
							{
								"field": "readOnly",
								"endsWith": [],
								"equals": ["true"],
								"notEndsWith": [],
								"notEquals": [],
								"notStartsWith": [],
								"startsWith": [],
							},
						],
					},
					{
						"__typename": "AWSCloudTrailAdvancedEventSelector",
						"name": "Management events selector",
						"fieldSelectors": [{
							"field": "eventCategory",
							"endsWith": [],
							"equals": ["Management"],
							"notEndsWith": [],
							"notEquals": [],
							"notStartsWith": [],
							"startsWith": [],
						}],
					},
				],
			},
		]},
	}]}}

	# check if the CloudTrail does not log read data events of S3 buckets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"metadata": {
			"id": "aws-account|779392177777",
			"displayName": "779392177777",
		},
		"cloudTrail": {"trails": [
			{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
					"displayName": "test-trail-1",
				},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"dataResources": [{
						"type": "AWS::S3::Object",
						"values": ["arn:aws:s3"],
					}],
					"readWriteType": "WRITE_ONLY",
				}],
			},
			{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
					"displayName": "test-trail-2",
				},
				"eventSelectors": [
					{
						"__typename": "AWSCloudTrailAdvancedEventSelector",
						"name": "",
						"fieldSelectors": [
							{
								"field": "eventCategory",
								"endsWith": [],
								"equals": ["Data"],
								"notEndsWith": [],
								"notEquals": [],
								"notStartsWith": [],
								"startsWith": [],
							},
							{
								"field": "resources.type",
								"endsWith": [],
								"equals": ["AWS::S3::Object"],
								"notEndsWith": [],
								"notEquals": [],
								"notStartsWith": [],
								"startsWith": [],
							},
							{
								"field": "readOnly",
								"endsWith": [],
								"equals": ["false"],
								"notEndsWith": [],
								"notEquals": [],
								"notStartsWith": [],
								"startsWith": [],
							},
						],
					},
					{
						"__typename": "AWSCloudTrailAdvancedEventSelector",
						"name": "Management events selector",
						"fieldSelectors": [{
							"field": "eventCategory",
							"endsWith": [],
							"equals": ["Management"],
							"notEndsWith": [],
							"notEquals": [],
							"notStartsWith": [],
							"startsWith": [],
						}],
					},
				],
			},
		]},
	}]}}
}
