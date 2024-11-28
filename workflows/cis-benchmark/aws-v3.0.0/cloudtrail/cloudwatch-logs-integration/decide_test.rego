package policy.aws.cloudtrail.cloudwatch_logs_integration

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

two_months_ago_string := date_string(time.add_date(now_ns, 0, -2, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_whether_cloudtrail_is_integrated_with_cloudwatch_logs if {
	# check if the CloudTrail is integrated with CloudWatch logs
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"cloudWatchLogGroup": {"arn": "arn:aws:logs:ap-northeast-1:779392177777:log-group:test-trail-1/CloudTrailLogs:*"},
			"status": {"latestCloudWatchLogsDeliveredAt": null},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"cloudWatchLogGroup": {"arn": "arn:aws:logs:ap-northeast-1:779392177777:log-group:test-trail-2/CloudTrailLogs:*"},
			"status": {"latestCloudWatchLogsDeliveredAt": today_string},
		},
	]}}]}}

	# check if the CloudTrail is not integrated with CloudWatch logs
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"cloudTrail": {"trails": [
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-1",
				"displayName": "test-trail-1",
			},
			"cloudWatchLogGroup": {"arn": "arn:aws:logs:ap-northeast-1:779392177777:log-group:test-trail-1/CloudTrailLogs:*"},
			"status": {"latestCloudWatchLogsDeliveredAt": ""},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-2",
				"displayName": "test-trail-2",
			},
			"cloudWatchLogGroup": {"arn": "arn:aws:logs:ap-northeast-1:779392177777:log-group:test-trail-2/CloudTrailLogs:*"},
			"status": {"latestCloudWatchLogsDeliveredAt": two_months_ago_string},
		},
		{
			"metadata": {
				"id": "aws-cloudtrail-trail|ap-northeast-1|test-trail-3",
				"displayName": "test-trail-3",
			},
			"cloudWatchLogGroup": {"arn": ""},
			"status": {"latestCloudWatchLogsDeliveredAt": today_string},
		},
	]}}]}}
}
