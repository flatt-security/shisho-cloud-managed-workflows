package policy.googlecloud.logmetric.network_route_changes

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	paths := cis_notification_paths(project)

	d := shisho.decision.googlecloud.logmetric.network_route_changes({
		"allowed": count(paths) > 0,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.logmetric.network_route_changes_payload({"cis_notification_implementations": paths}),
	})
}

# The Cloud Logging Log Metrics pattern to match the events to notify.
# This includes one defined in CIS Google Cloud Platform Foundations Benchmark v1.3.0 defines, or one defined in Security Command Center.
# If you achieve the similar goal with a different pattern, you can replace this pattern with yours or add your pattern to the array to let it pass this policy.
patterns := ["resource.type=\"gce_route\" AND (protoPayload.methodName:\"compute.routes.delete\" OR protoPayload.methodName:\"compute.routes.insert\")"]

# Find a path that implements the notification from Cloud Logging to Cloud Monitoring as described in CIS Google Cloud Platform Foundations Benchmark v1.3.0
cis_notification_paths(project) := x {
	x := [{
		"metric_name": metric.metadata.displayName,
		"alert_policy_name": policy.displayName,
	} |
		# Find a metric that matches the pattern ....
		metric := project.cloudLogging.metrics[_]
		filter := replace(metric.filter, "\n", " ")
		filter == patterns[_]

		# Find a active policy that has a condition for the metric
		policy := project.cloudMonitoring.policies[_]
		policy.enabled == true
		has_condition_for(policy, metric.metadata.displayName)
	]
} else = []

has_condition_for(policy, metric_name) {
	query := sprintf("metric.type = \"logging.googleapis.com/user/%s\"", [metric_name])

	condition := policy.conditions[_]
	contains(condition.threshold.filter, query)
} else = false
