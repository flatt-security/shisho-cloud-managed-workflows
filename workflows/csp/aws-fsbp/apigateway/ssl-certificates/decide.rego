package policy.aws.apigateway.ssl_certificates

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	api := account.apigateway.apis[_]

	stages := stages_with_certificate(api.stages)
	count(stages) > 0

	d := shisho.decision.aws.apigateway.ssl_certificates({
		"allowed": allow_if_excluded(is_ssl_certificate_configured(stages), api),
		"subject": api.metadata.id,
		"payload": shisho.decision.aws.apigateway.ssl_certificates_payload({"stages": stages}),
	})
}

is_ssl_certificate_configured(stages) = false {
	stage := stages[_]
	stage.certificate_id == ""
} else = true

stages_with_certificate(stages) := x {
	x := [{"name": stage.name, "certificate_id": stage.clientCertificateId} |
		stage := stages[_]
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
