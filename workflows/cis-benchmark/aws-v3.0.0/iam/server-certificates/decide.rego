package policy.aws.iam.server_certificates

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	certificate := account.iam.serverCertificates[_]

	d := shisho.decision.aws.iam.server_certificates({
		"allowed": expired_certificate(certificate) == false,
		"subject": certificate.metadata.id,
		"payload": shisho.decision.aws.iam.server_certificates_payload({
			"name": certificate.name,
			"expired_at": certificate.expiredAt,
		}),
	})
}

expired_certificate(certificate) {
	timestamp_ns(certificate.expiredAt) < time.now_ns()
} else = false

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)
