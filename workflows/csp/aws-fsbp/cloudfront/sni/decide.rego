package policy.aws.cloudfront.sni

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	allowed := used_sni(dist.viewerCertificate)

	d := shisho.decision.aws.cloudfront.sni({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.sni_payload({"use_sni": allowed}),
	})
}

used_sni(viewer_certificate) {
	viewer_certificate.cloudFrontDefaultCertificate == false
	viewer_certificate.sslSupportMethod == "SNI_ONLY"
} else = false

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
