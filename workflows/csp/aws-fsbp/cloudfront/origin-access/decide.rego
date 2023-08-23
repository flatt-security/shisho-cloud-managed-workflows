package policy.aws.cloudfront.origin_access

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	origins := s3_backend_origins(dist)
	allowed := includes_unallowed_origins(origins) == false
	d := shisho.decision.aws.cloudfront.origin_access_control({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.origin_access_control_payload({"origins": origins}),
		"severity": custom_severity(origins),
	})
}

s3_backend_origins(dist) = [{
	"id": o.id,
	"domain_name": o.domainName,
	"origin_access_control_configured": string_or_empty(o.accessControlId),
	"origin_access_identity_configured": string_or_empty(o.backend.accessIdentityId),
} |
	o := dist.origins[_]
	o.backend.__typename == "AWSCloudFrontDistributionOriginBackendS3Bucket"
]

string_or_empty(s) := s {
	s != null
} else := ""

includes_unallowed_origins(origins) {
	o := origins[_]
	o.origin_access_control_configured == ""
} else := false

custom_severity(origins) := s {
	candidates := [cs |
		o := origins[_]
		cs := custom_severity_of(o)
		cs != null
	]
	count(candidates) > 0
	s := max(candidates)
} else := null

custom_severity_of(o) := shisho.decision.severity_low {
	o.origin_access_control_configured == ""
	o.origin_access_identity_configured != ""
} else := null

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
