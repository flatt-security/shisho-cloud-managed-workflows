package policy.aws.cloudfront.root_object

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := has_default_root_object(dist.config)
	d := shisho.decision.aws.cloudfront.default_root_object({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.default_root_object_payload({"default_root_object": default_root_object(dist.config)}),
		"severity": severity(dist),
	})
}

# Identifies the severity of this issue.
severity(dist) := shisho.decision.severity_critical {
	o := dist.origins[_]
	o.backend != null
	o.backend.__typename == "AWSCloudFrontDistributionOriginBackendS3Bucket"

	has_s3_list_object_rp(o.backend)
} else := shisho.decision.severity_info

has_default_root_object(cfg) {
	default_root_object(cfg) != ""
} else := false

default_root_object(cfg) := cfg.defaultRootObject {
	cfg.defaultRootObject != null
	cfg.defaultRootObject != ""
} else := ""

# If the backend S3 resource policy does not allow the ListObject action, the severity should be lower.
has_s3_list_object_rp(backend) {
	policy := json.unmarshal(backend.bucket.policy.rawDocument)

	s := policy.Statement[_]
	s.Effect == "Allow"
	s.Action[_] == "s3:ListBucket"
} else := false

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
