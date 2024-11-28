package policy.aws.acm.certificate_key_algorithm

import data.shisho

# this is the list of acceoted key algorithms. Please adjust to your needs.
# Please check the avaialavble key algorithms in the AWS documentation:
# https://docs.aws.amazon.com/acm/latest/userguide/import-certificate-prerequisites.html
accepted_key_algorithms := [
	"RSA_2048",
	"RSA_3072",
	"RSA_4096",
	"EC_PRIME256V1",
	"EC_SECP384R1",
	"EC_SECP521R1",
]

decisions[d] {
	account := input.aws.accounts[_]
	certificate := account.acm.certificates[_]

	d := shisho.decision.aws.acm.certificate_key_algorithm({
		"allowed": allow_if_excluded(used_accepted_key_algorithm(certificate.keyAlgorithm), certificate),
		"subject": certificate.metadata.id,
		"payload": shisho.decision.aws.acm.certificate_key_algorithm_payload({"key_algorithm": certificate.keyAlgorithm}),
	})
}

used_accepted_key_algorithm(key_algorithm) {
	accepted_key_algorithms[_] == key_algorithm
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
