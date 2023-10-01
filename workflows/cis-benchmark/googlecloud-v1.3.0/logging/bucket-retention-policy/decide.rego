package policy.googlecloud.logging.bucket_retention_policy

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	# For a sink with a Cloud Storage bucket as a destination ...
	sink := project.cloudLogging.sinks[_]
	startswith(sink.destination, "storage.googleapis.com/")

	# ... confirm that the bucket has a locked retention policy.
	name := storage_bucket_name(sink.destination)
	locked := storage_bucket_locked(name, project)

	d := shisho.decision.googlecloud.logging.bucket_retention_policy({
		"allowed": locked,
		"subject": sink.metadata.id,
		"payload": shisho.decision.googlecloud.logging.bucket_retention_policy_payload({
			"storage_bucket_name": name,
			"locked": locked,
			"retention_period": storage_bucket_retention_period(name, project),
		}),
	})
}

storage_bucket_name(destination) := bucket_name {
	bucket_name := trim_prefix(destination, "storage.googleapis.com/")
}

storage_bucket_locked(bucket_name, project) {
	bucket := project.cloudStorage.buckets[_]
	bucket.name == bucket_name
	bucket.retentionPolicy.isLocked == true
} else = false

storage_bucket_retention_period(bucket_name, project) := p {
	bucket := project.cloudStorage.buckets[_]
	bucket.name == bucket_name

	p := bucket.retentionPolicy.retentionPeriod
} else = 0
