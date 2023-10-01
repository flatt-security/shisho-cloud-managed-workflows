package policy.aws.iam.server_certificates

import data.shisho
import future.keywords

in_one_year_string := date_string(time.add_date(time.now_ns(), 1, 0, 0))

date_string(date_ns) := date_as_string if {
	date := time.date(date_ns)
	date_as_string := sprintf("%d-%s-%sT00:00:00Z", [date[0], format_digit(date[1]), format_digit(date[2])])
}

format_digit(digit) = formatted_digit if {
	digit < 10
	formatted_digit := sprintf("0%d", [digit])
} else = sprintf("%d", [digit])

test_whether_the_server_certificates_are_not_expired if {
	# check if the server certificates are not expired
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [
		{"iam": {"serverCertificates": [
			{
				"metadata": {
					"id": "aws-iam-server-certificate|7e81eedf-6bfa-4e28-b1be-f527615fab8b",
					"displayName": "test-certificate-1",
				},
				"name": "test-certificate-1",
				"expiredAt": in_one_year_string,
			},
			{
				"metadata": {
					"id": "aws-iam-server-certificate|f85496c1-970a-4ab1-8204-63d04f4cec01",
					"displayName": "test-certificate-2",
				},
				"name": "test-certificate-2",
				"expiredAt": in_one_year_string,
			},
		]}},
		{"iam": {"serverCertificates": [
			{
				"metadata": {
					"id": "aws-iam-server-certificate|74430d6f-8630-4b8b-99f9-29e031136836",
					"displayName": "test-certificate-3",
				},
				"name": "test-certificate-3",
				"expiredAt": in_one_year_string,
			},
			{
				"metadata": {
					"id": "aws-iam-server-certificate|92424574-3932-4963-a20b-9fb8c608513e",
					"displayName": "test-certificate-4",
				},
				"name": "test-certificate-4",
				"expiredAt": in_one_year_string,
			},
		]}},
	]}}

	# check if the server certificates are expired
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [
		{"iam": {"serverCertificates": [
			{
				"metadata": {
					"id": "aws-iam-server-certificate|7e81eedf-6bfa-4e28-b1be-f527615fab8b",
					"displayName": "test-certificate-1",
				},
				"name": "test-certificate-1",
				"expiredAt": "2020-05-01T10:00:00Z",
			},
			{
				"metadata": {
					"id": "aws-iam-server-certificate|f85496c1-970a-4ab1-8204-63d04f4cec01",
					"displayName": "test-certificate-2",
				},
				"name": "test-certificate-2",
				"expiredAt": "2021-05-01T10:00:00Z",
			},
		]}},
		{"iam": {"serverCertificates": [
			{
				"metadata": {
					"id": "aws-iam-server-certificate|74430d6f-8630-4b8b-99f9-29e031136836",
					"displayName": "test-certificate-3",
				},
				"name": "test-certificate-3",
				"expiredAt": "2022-05-01T10:00:00Z",
			},
			{
				"metadata": {
					"id": "aws-iam-server-certificate|92424574-3932-4963-a20b-9fb8c608513e",
					"displayName": "test-certificate-4",
				},
				"name": "test-certificate-4",
				"expiredAt": "2023-05-01T10:00:00Z",
			},
		]}},
	]}}
}
