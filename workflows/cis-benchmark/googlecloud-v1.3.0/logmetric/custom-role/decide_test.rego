package policy.googlecloud.logmetric.custom_role_changes

import data.shisho
import future.keywords

test_whether_log_metrics_are_configured_for_custom_role_changes if {
	# check if the log metrics are configured for custom role changes
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"metrics": [{
				"metadata": {
					"id": "googlecloud-cl-metric|514897777777|test-log-metric-1",
					"displayName": "test-log-metric-1",
				},
				"filter": "resource.type=\"iam_role\" AND (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")",
			}]},
			"cloudMonitoring": {"policies": [
				{
					"displayName": "test-alert-policy",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/disk/bytes_used\""}}],
				},
				{
					"displayName": "test-alert-policy-2",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"logging_sink\" AND metric.type = \"logging.googleapis.com/user/test-log-metric-1\""}}],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"metrics": [{
				"metadata": {
					"id": "googlecloud-cl-metric|514898888888|test-log-metric-2",
					"displayName": "test-log-metric-2",
				},
				"filter": "resource.type=\"iam_role\" AND (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")",
			}]},
			"cloudMonitoring": {"policies": [
				{
					"displayName": "test-alert-policy-3",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/disk/bytes_used\""}}],
				},
				{
					"displayName": "test-alert-policy-4",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"logging_sink\" AND metric.type = \"logging.googleapis.com/user/test-log-metric-2\""}}],
				},
			]},
		},
	]}}

	# check if the log metrics are configured for custom role changes
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"metrics": [{
				"metadata": {
					"id": "googlecloud-cl-metric|514897777777|test-log-metric-1",
					"displayName": "test-log-metric-1",
				},
				"filter": "resource.type=\"iam_role\" AND (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")",
			}]},
			"cloudMonitoring": {"policies": [
				{
					"displayName": "test-alert-policy",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/disk/bytes_used\""}}],
				},
				{
					"displayName": "test-alert-policy-2",
					"enabled": false,
					"conditions": [{"threshold": {"filter": "resource.type = \"logging_sink\" AND metric.type = \"logging.googleapis.com/user/test-log-metric-1\""}}],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"metrics": [{
				"metadata": {
					"id": "googlecloud-cl-metric|514898888888|test-log-metric-2",
					"displayName": "test-log-metric-2",
				},
				"filter": "resource.type=\"iam_role\"\nAND protoPayload.methodName = \"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\"",
			}]},
			"cloudMonitoring": {"policies": [
				{
					"displayName": "test-alert-policy-3",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/disk/bytes_used\""}}],
				},
				{
					"displayName": "test-alert-policy-4",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"logging_sink\" AND metric.type = \"logging.googleapis.com/user/test-log-metric-2\""}}],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514899999999",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"metrics": [{
				"metadata": {
					"id": "googlecloud-cl-metric|514899999999|test-log-metric-1",
					"displayName": "test-log-metric-1",
				},
				"filter": "resource.type=\"iam_role\" AND (protoPayload.methodName=\"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")",
			}]},
			"cloudMonitoring": {"policies": [
				{
					"displayName": "test-alert-policy",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"cloudsql_database\" AND metric.type = \"cloudsql.googleapis.com/database/disk/bytes_used\""}}],
				},
				{
					"displayName": "test-alert-policy-2",
					"enabled": true,
					"conditions": [{"threshold": {"filter": "resource.type = \"logging_sink\" AND metric.type = \"logging.googleapis.com/user/dummy-test-log-metric-100\""}}],
				},
			]},
		},
	]}}
}
