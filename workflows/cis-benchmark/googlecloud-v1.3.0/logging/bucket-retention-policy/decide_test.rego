package policy.googlecloud.logging.bucket_retention_policy

import data.shisho
import future.keywords

test_whether_retention_policies_with_bucket_lock_are_configured_for_sinks if {
	# check if the retention policies with bucket lock of Cloud Storage buckets are configured for sinks
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"cloudLogging": {"sinks": [
			{
				"metadata": {
					"id": "googlecloud-cl-sink|51489777777|test-sink-1",
					"displayName": "test-sink-1",
				},
				"destination": "storage.googleapis.com/test-bucket-shisho-security-12",
			},
			{
				"metadata": {
					"id": "googlecloud-cl-sink|51489777777|test-sink-2",
					"displayName": "test-sink-2",
				},
				"destination": "storage.googleapis.com/test-bucket-shisho-security-13",
			},
			{
				"metadata": {
					"id": "googlecloud-cl-sink|51489777777|_Default",
					"displayName": "_Default",
				},
				"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/_Default",
			},
		]},
		"cloudStorage": {"buckets": [
			{
				"name": "test-bucket-for-dataproc-1",
				"retentionPolicy": null,
			},
			{
				"name": "test-bucket-shisho-security",
				"retentionPolicy": null,
			},
			{
				"name": "test-bucket-shisho-security-12",
				"retentionPolicy": {"isLocked": true, "retentionPeriod": 123},
			},
			{
				"name": "test-bucket-shisho-security-13",
				"retentionPolicy": {"isLocked": true, "retentionPeriod": 123},
			},
		]},
	}]}}

	# check if the retention policies with bucket lock of Cloud Storage buckets are not configured for sinks
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"cloudLogging": {"sinks": [
			{
				"metadata": {
					"id": "googlecloud-cl-sink|51489777777|test-sink-1",
					"displayName": "test-sink-1",
				},
				"destination": "storage.googleapis.com/test-bucket-shisho-security-12",
			},
			{
				"metadata": {
					"id": "googlecloud-cl-sink|51489777777|test-sink-2",
					"displayName": "test-sink-2",
				},
				"destination": "storage.googleapis.com/test-bucket-shisho-security-13",
			},
			{
				"metadata": {
					"id": "googlecloud-cl-sink|51489777777|_Default",
					"displayName": "_Default",
				},
				"destination": "logging.googleapis.com/projects/test-project-1/locations/global/buckets/_Default",
			},
		]},
		"cloudStorage": {"buckets": [
			{
				"name": "test-bucket-for-dataproc-1",
				"retentionPolicy": null,
			},
			{
				"name": "test-bucket-shisho-security",
				"retentionPolicy": null,
			},
			{
				"name": "test-bucket-shisho-security-12",
				"retentionPolicy": {"isLocked": false, "retentionPeriod": 123},
			},
			{
				"name": "test-bucket-shisho-security-13",
				"retentionPolicy": null,
			},
		]},
	}]}}
}
