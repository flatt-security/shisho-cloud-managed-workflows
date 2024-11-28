package policy.aws.s3.bucket_event_notifications

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	configs := event_notification_configs(bucket.notificationConfiguration)

	d := shisho.decision.aws.s3.bucket_event_notifications({
		"allowed": allow_if_excluded(is_event_notification_enabled(configs), bucket),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_event_notifications_payload(configs),
	})
}

is_event_notification_enabled(configs) {
	[
		configs.notification_eventbridge_enabled,
		count(configs.notification_lambda_function_arns) > 0,
		count(configs.notification_sns_topic_arns) > 0,
		count(configs.notification_sqs_queue_arns) > 0,
	][_] == true
} else = false

event_notification_configs(config) := {
	"notification_eventbridge_enabled": config.eventBridgeConfiguration.enabled,
	"notification_lambda_function_arns": [arn | arn := config.lambdaFunctionConfigurations[_].arn],
	"notification_sns_topic_arns": [arn | arn := config.queueConfigurations[_].arn],
	"notification_sqs_queue_arns": [arn | arn := config.topicConfigurations[_].arn],
} {
	config != null
} else = {
	"notification_eventbridge_enabled": false,
	"notification_lambda_function_arns": [],
	"notification_sns_topic_arns": [],
	"notification_sqs_queue_arns": [],
}

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
