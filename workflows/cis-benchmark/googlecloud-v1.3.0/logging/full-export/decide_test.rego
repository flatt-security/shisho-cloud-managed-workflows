package policy.googlecloud.logging.full_export

import data.shisho
import future.keywords

test_whether_logging_sinks_are_configured_for_all_log_entries if {
	# check if the logging sinks are configured for all log entries
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"sinks": [
				{
					"name": "test-sink-1",
					"filter": "",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
				{
					"name": "test-sink-2",
					"filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"sinks": [
				{
					"name": "test-empty-filter-sink-1",
					"filter": "",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
				{
					"name": "sink-1",
					"filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
			]},
		},
	]}}

	# check if the logging sinks are not configured for all log entries
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [
		{
			"metadata": {
				"id": "googlecloud-project|514897777777",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"sinks": [
				{
					"name": "sink-1",
					"filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
				{
					"name": "sink-1",
					"filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
			]},
		},
		{
			"metadata": {
				"id": "googlecloud-project|514898888888",
				"displayName": "test-project-1",
			},
			"cloudLogging": {"sinks": [
				{
					"name": "sink-1",
					"filter": "",
					"destination": "",
					"exclusions": [],
				},
				{
					"name": "sink-1",
					"filter": "LOG_ID(\"cloudaudit.googleapis.com/activity\")",
					"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/test-sink-1",
					"exclusions": [],
				},
			]},
		},
	]}}
}
