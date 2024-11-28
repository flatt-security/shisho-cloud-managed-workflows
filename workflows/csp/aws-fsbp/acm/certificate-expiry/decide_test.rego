package policy.aws.acm.certificate_expiry

import data.shisho
import future.keywords

now_ns := time.now_ns()

today_string := date_string(now_ns)

within_two_months_string := date_string(time.add_date(now_ns, 0, 2, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT23:59:59Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_whether_expiry_for_acm_certificates_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"acm": {"certificates": [
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796aa",
				"displayName": "flatt-1.tech.test",
			},
			"renewalEligibility": "ELIGIBLE",
			"notAfter": within_two_months_string,
		},
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796bb",
				"displayName": "flatt-2.tech.test",
			},
			"renewalEligibility": "INELIGIBLE",
			"notAfter": null,
		},
	]}}]}}
}

test_whether_expiry_for_acm_certificates_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"acm": {"certificates": [
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796aa",
				"displayName": "flatt-1.tech.test",
			},
			"renewalEligibility": "ELIGIBLE",
			"notAfter": today_string,
		},
		{
			"metadata": {
				"id": "aws-acm-certificate|ap-northeast-1|abb2f94e-cc3d-48e4-a8a2-57c3945796bb",
				"displayName": "flatt-2.tech.test",
			},
			"renewalEligibility": "ELIGIBLE",
			"notAfter": today_string,
		},
	]}}]}}
}
