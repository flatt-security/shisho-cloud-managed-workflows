package policy.aws.cloudfront.default_certificate

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := dist.viewerCertificate.cloudFrontDefaultCertificate == false

	d := shisho.decision.aws.cloudfront.default_certificate({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.default_certificate_payload({"use_custom_certificate": allowed}),
	})
}

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
