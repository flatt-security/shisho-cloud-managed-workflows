package policy.aws.logmetric.route_table_changes

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	paths := cis_based_notification_paths(account)

	d := shisho.decision.aws.logmetric.route_table_changes({
		"allowed": count(paths) > 0,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.logmetric.route_table_changes_payload({"cis_notification_implementations": paths}),
	})
}

# The CloudWatch LogMetric pattern to match the events to notify.
# This is exactly same as CIS AWS Foundations Benchmark v1.5.0 defines. 
# If you achieve the similar goal with a different pattern, you can replace this pattern with yours or add your pattern to the array to let it pass this policy.
patterns := ["{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"]

# Find a path that implements the notification from CloudTrail to a SNS topic as described in CIS AWS Foundations Benchmark v1.5.0.
cis_based_notification_paths(account) := x {
	x := [path |
		# (1) Find a trail that cover all regions, log events actively, and include management events....
		trail := account.cloudTrail.trails[_]
		trail.isMultiRegionTrail == true
		trail.status.isLogging == true
		all_management_rw_events_recorded(trail.eventSelectors)

		# ... and a filter that matches the CIS pattern...
		filter := trail.cloudWatchLogGroup.metricFilters[_]
		filter.pattern == patterns[_]

		# ... and a metric on the filter.
		metric := filter.metricTransformations[_]

		# (2) Find an alarm that uses the metric.
		alarm := account.cloudWatch.alarms[_]
		alarm.metricName == metric.name

		# (3) Find a SNS topic that the alarm notifies and has at least one subscription.
		sns_topics := sns_topic_to_be_notified(alarm.alarmActions)
		topic := sns_topics[_]
		count(topic.subscriptions) > 0

		# Now (1) - (3) form a path from CloudTrail to a SNS topic (and somewhere else connected to the topic).
		path := {
			"trail_name": trail.metadata.displayName,
			"metric_name": metric.name,
			"alarm_name:": alarm.metadata.displayName,
			"sns_topic_arn": topic.arn,
		}
	]
} else = []

# Check whether all management events are recorded or not.
# This function cannot cover advanced event selectors as CIS AWS Foundations Benchmark v1.5.0 does not allow them as of now.
all_management_rw_events_recorded(selectors) {
	selector = selectors[_]
	selector.__typename == "AWSCloudTrailBasicEventSelector"
	selector.includeManagementEvents == true
	selector.readWriteType == "ALL"
} else {
	selector = selectors[_]
	selector.__typename == "AWSCloudTrailAdvancedEventSelector"

	contains_field_eq_selector(selector.fieldSelectors, "eventCategory", "Management")
	not contains_field_eq_selector(selector.fieldSelectors, "readOnly", "true")
	not contains_field_eq_selector(selector.fieldSelectors, "readOnly", "false")
} else = false

contains_field_eq_selector(field_selectors, field, value) {
	field_selector := field_selectors[_]
	field_selector.field == field
	eq := field_selector.equals[_]
	eq == value
} else = false

sns_topic_to_be_notified(actions) := x {
	x := [action.topic |
		action := actions[_]
		action.__typename == "AWSCloudWatchAlarmActionNotification"
		startswith(action.topic.arn, "arn:aws:sns:")
	]
} else = []
