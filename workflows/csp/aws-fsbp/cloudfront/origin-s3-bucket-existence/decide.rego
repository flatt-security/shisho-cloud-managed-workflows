package policy.aws.cloudfront.origin_s3_bucket_existence

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	buckets := s3_buckets(dist.origins)

	d := shisho.decision.aws.cloudfront.origin_s3_bucket_existence({
		"allowed": allow_if_excluded(non_existent_origins(buckets) == false, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.origin_s3_bucket_existence_payload({"buckets": buckets}),
	})
}

non_existent_origins(buckets) {
	bucket := buckets[_]
	bucket.existent == false
} else = false

s3_buckets(origins) := x {
	x := [{"domain_name": origin.domainName, "existent": existent} |
		origin := origins[_]
		split_domain_name := split(origin.domainName, ".")
		split_domain_name[1] == "s3"
		existent := origin.backend.bucket != null
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
