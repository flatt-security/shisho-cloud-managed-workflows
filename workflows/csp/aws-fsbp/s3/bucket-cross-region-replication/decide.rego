package policy.aws.s3.bucket_cross_region_replication

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	bucket := account.s3.buckets[_]

	bucket.replicationConfiguration != null
	count(bucket.replicationConfiguration.rules) > 0

	destinations := replication_destinations(
		bucket.replicationConfiguration.rules,
		bucket.region, account.s3.buckets,
	)

	d := shisho.decision.aws.s3.bucket_cross_region_replication({
		"allowed": allow_if_excluded(
			cross_region_replication_enabled(
				bucket.region,
				destinations,
			),
			bucket,
		),
		"subject": bucket.metadata.id,
		"payload": shisho.decision.aws.s3.bucket_cross_region_replication_payload({"destinations": destinations}),
	})
}

cross_region_replication_enabled(region, destinations) {
	destination := destinations[_]
	region != destination.region
} else = false

replication_destinations(rules, region, buckets) := x {
	x := [{"bucket": bucket_name, "region": bucket.region} |
		rule := rules[_]
		rule.status == "ENABLED"
		bucket_name := trim_prefix(rule.destination.bucket, "arn:aws:s3:::")

		bucket := buckets[_]
		bucket.metadata.displayName == bucket_name
	]
} else = []

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
