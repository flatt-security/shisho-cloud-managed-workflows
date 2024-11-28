package policy.aws.acm.certificate_expiry

import data.shisho

# the default is 30 days. Please adjust to your needs.
accepted_duration_for_renewal := 30

decisions[d] {
	account := input.aws.accounts[_]
	certificate := account.acm.certificates[_]

	allowed := renewal_config(
		certificate.renewalEligibility,
		renewed_within_specified_days(
			timestamp_ns(certificate.notAfter),
			accepted_duration_for_renewal,
		),
	)

	d := shisho.decision.aws.acm.certificate_expiry({
		"allowed": allow_if_excluded(allowed, certificate),
		"subject": certificate.metadata.id,
		"payload": shisho.decision.aws.acm.certificate_expiry_payload({
			"renewal_eligibility": allowed,
			"expiry_date": expiry_date(certificate.notAfter),
		}),
	})
}

renewal_config(renewal_eligibility, renewal_status) {
	[
		renewal_eligibility == "INELIGIBLE",
		renewal_status == true,
	][_] == true
} else = false

expiry_date(not_after) = not_after {
	not_after != null
} else = ""

renewed_within_specified_days(ts, d) {
	now := time.now_ns()

	diff_ns := ts - now

	# True if the difference is less than `d` days
	diff_ns > (((1000000000 * 60) * 60) * 24) * d
} else = false

timestamp_ns(t) := 0 {
	t == null
} else := time.parse_rfc3339_ns(t)

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
