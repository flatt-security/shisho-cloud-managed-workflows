package policy.aws.flatt.cloudfront.tls_version

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1",
		"kind": "aws_cloudfront_tls_version",
		"subject": dist.metadata.id,
		"locator": "",
		"severity": shisho.decision.severity_high,
		"allowed": allow_if_excluded(has_unacceptable_minimum_version(dist) == false, dist),
		"payload": json.marshal({
			"minimum_protocol_version": minimum_protocol_version(dist),
			"is_default_certificate": is_default_certificate(dist),
		}),
	})
}

has_unacceptable_minimum_version(dist) {
	minimum_protocol_version(dist) == unacceptable_tls_version[_]
} else = false

unacceptable_tls_version = [
	"SSLV3",
	"TLSV1",
	"TLSV1_2016",
	"TLSV1_1_2016",
	"",
]

minimum_protocol_version(dist) := dist.viewerCertificate.minimumProtocolVersion {
	dist.viewerCertificate != null
} else := ""

is_default_certificate(dist) {
	dist.viewerCertificate != null
	dist.viewerCertificate.cloudFrontDefaultCertificate
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
