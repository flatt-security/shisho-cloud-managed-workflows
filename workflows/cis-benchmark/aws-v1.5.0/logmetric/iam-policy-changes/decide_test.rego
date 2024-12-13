package policy.aws.logmetric.iam_policy_changes

import data.shisho
import future.keywords

test_whether_log_metric_filter_and_alarm_exist_for_iam_policy_changes if {
	# check if there is a log metric filter and alarm for IAM policy changes
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"cloudTrail": {"trails": [
				{
					"metadata": {
						"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
						"displayName": "aws-controltower-BaselineCloudTrail",
					},
					"isMultiRegionTrail": true,
					"cloudWatchLogGroup": {
						"metadata": {
							"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
							"displayName": "aws-controltower/CloudTrailLogs",
						},
						"arn": "arn:aws:logs:ap-northeast-1:779397777777:log-group:aws-controltower/CloudTrailLogs:*",
						"metricFilters": [{
							"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}",
							"metricTransformations": [{"name": "test-metric-name-2"}],
						}],
					},
					"status": {"isLogging": true},
					"eventSelectors": [{
						"__typename": "AWSCloudTrailBasicEventSelector",
						"includeManagementEvents": true,
						"readWriteType": "ALL",
					}],
				},
				{
					"metadata": {
						"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
						"displayName": "test-trail-2",
					},
					"isMultiRegionTrail": true,
					"cloudWatchLogGroup": {
						"metadata": {
							"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-cloudtrail-logs-779397777777-87777777",
							"displayName": "aws-cloudtrail-logs-779397777777-87777777",
						},
						"arn": "arn:aws:logs:ap-northeast-1:779397777777:log-group:aws-cloudtrail-logs-779397777777-87777777:*",
						"metricFilters": [],
					},
					"status": {"isLogging": true},
					"eventSelectors": [
						{
							"__typename": "AWSCloudTrailAdvancedEventSelector",
							"name": "",
							"fieldSelectors": [
								{
									"field": "eventCategory",
									"equals": ["Data"],
								},
								{
									"field": "resources.type",
									"equals": ["AWS::S3::Object"],
								},
							],
						},
						{
							"__typename": "AWSCloudTrailAdvancedEventSelector",
							"name": "Management events selector",
							"fieldSelectors": [{
								"field": "eventCategory",
								"equals": ["Management"],
							}],
						},
					],
				},
			]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-3",
					"displayName": "test-alarm-3",
				},
				"name": "test-alarm-3",
				"metricName": "test-metric-name-2",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-1.fifo",
							"displayName": "test-topic-1.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779397777777:test-topic-1.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779397777777:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779397777777"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779398888888",
				"displayName": "779398888888",
			},
			"cloudTrail": {"trails": [
				{
					"metadata": {
						"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
						"displayName": "aws-controltower-BaselineCloudTrail",
					},
					"isMultiRegionTrail": true,
					"cloudWatchLogGroup": {
						"metadata": {
							"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
							"displayName": "aws-controltower/CloudTrailLogs",
						},
						"arn": "arn:aws:logs:ap-northeast-1:779398888888:log-group:aws-controltower/CloudTrailLogs:*",
						"metricFilters": [{
							"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
							"metricTransformations": [{"name": "test-metric-name-3"}],
						}],
					},
					"status": {"isLogging": true},
					"eventSelectors": [{
						"__typename": "AWSCloudTrailBasicEventSelector",
						"includeManagementEvents": true,
						"readWriteType": "ALL",
					}],
				},
				{
					"metadata": {
						"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-3",
						"displayName": "test-trail-3",
					},
					"isMultiRegionTrail": true,
					"cloudWatchLogGroup": {
						"metadata": {
							"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-cloudtrail-logs-779398888888-88888888",
							"displayName": "aws-cloudtrail-logs-779398888888-88888888",
						},
						"arn": "arn:aws:logs:ap-northeast-1:779398888888:log-group:aws-cloudtrail-logs-779398888888-88888888:*",
						"metricFilters": [],
					},
					"status": {"isLogging": true},
					"eventSelectors": [
						{
							"__typename": "AWSCloudTrailAdvancedEventSelector",
							"name": "",
							"fieldSelectors": [
								{
									"field": "eventCategory",
									"equals": ["Data"],
								},
								{
									"field": "resources.type",
									"equals": ["AWS::S3::Object"],
								},
							],
						},
						{
							"__typename": "AWSCloudTrailAdvancedEventSelector",
							"name": "Management events selector",
							"fieldSelectors": [{
								"field": "eventCategory",
								"equals": ["Management"],
							}],
						},
					],
				},
			]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-2.fifo",
							"displayName": "test-topic-2.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779398888888:test-topic-2.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779398888888:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779398888888"}],
					},
				}],
			}]},
		},
	]}}

	# check if there is not a log metric filter and alarm for IAM policy changes
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 8 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": false,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779397777777:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [{"name": "test-metric-name-2"}],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-3",
					"displayName": "test-alarm-3",
				},
				"name": "test-alarm-3",
				"metricName": "test-metric-name-2",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-1.fifo",
							"displayName": "test-topic-1.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779397777777:test-topic-1.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779397777777:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779397777777"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779398888888",
				"displayName": "779398888888",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779398888888:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [{"name": "test-metric-name-3"}],
					}],
				},
				"status": {"isLogging": false},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-2.fifo",
							"displayName": "test-topic-2.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779398888888:test-topic-2.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779398888888:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779398888888"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779399999999",
				"displayName": "779399999999",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779399999999:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [{"name": "test-metric-name-3"}],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": false,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-2.fifo",
							"displayName": "test-topic-2.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779399999999:test-topic-2.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779399999999:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779399999999"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779390000000",
				"displayName": "779390000000",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779390000000:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [{"name": "test-metric-name-3"}],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "READ_ONLY",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-2.fifo",
							"displayName": "test-topic-2.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779390000000:test-topic-2.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779390000000:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779390000000"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779391111111",
				"displayName": "779391111111",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779391111111:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-2.fifo",
							"displayName": "test-topic-2.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779391111111:test-topic-2.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779391111111:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779391111111"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779392222222",
				"displayName": "779392222222",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779392222222:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [{"name": "test-metric-name-4"}],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-2.fifo",
							"displayName": "test-topic-2.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779392222222:test-topic-2.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779392222222:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779392222222"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779394444444",
				"displayName": "779394444444",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779394444444:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "ERROR",
						"metricTransformations": [{"name": "test-metric-name-3"}],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-3.fifo",
							"displayName": "test-topic-3.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779394444444:test-topic-3.fifo",
						"subscriptions": [{"arn": "arn:aws:sns:ap-northeast-1:779394444444:aws-controltower-SecurityNotifications:1e9d59ad-edb8-4af7-a566-779394444444"}],
					},
				}],
			}]},
		},
		{
			"metadata": {
				"id": "aws-account|779395555555",
				"displayName": "779395555555",
			},
			"cloudTrail": {"trails": [{
				"metadata": {
					"id": "aws-cloudtrail-trail|ap-northeast-1|aws-controltower-BaselineCloudTrail",
					"displayName": "aws-controltower-BaselineCloudTrail",
				},
				"isMultiRegionTrail": true,
				"cloudWatchLogGroup": {
					"metadata": {
						"id": "aws-cloudwatch-log-group|ap-northeast-1|aws-controltower/CloudTrailLogs",
						"displayName": "aws-controltower/CloudTrailLogs",
					},
					"arn": "arn:aws:logs:ap-northeast-1:779395555555:log-group:aws-controltower/CloudTrailLogs:*",
					"metricFilters": [{
						"pattern": "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventNa me=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolic y)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=Del etePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersi on)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.event Name=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGr oupPolicy)||($.eventName=DetachGroupPolicy)}",
						"metricTransformations": [{"name": "test-metric-name-3"}],
					}],
				},
				"status": {"isLogging": true},
				"eventSelectors": [{
					"__typename": "AWSCloudTrailBasicEventSelector",
					"includeManagementEvents": true,
					"readWriteType": "ALL",
				}],
			}]},
			"cloudWatch": {"alarms": [{
				"metadata": {
					"id": "aws-cloudwatch-alarm|ap-northeast-1|test-alarm-4",
					"displayName": "test-alarm-4",
				},
				"name": "test-alarm-4",
				"metricName": "test-metric-name-3",
				"alarmActions": [{
					"__typename": "AWSCloudWatchAlarmActionNotification",
					"topic": {
						"metadata": {
							"id": "aws-sns-topic|ap-northeast-1|test-topic-3.fifo",
							"displayName": "test-topic-3.fifo",
						},
						"arn": "arn:aws:sns:ap-northeast-1:779395555555:test-topic-3.fifo",
						"subscriptions": [],
					},
				}],
			}]},
		},
	]}}
}
