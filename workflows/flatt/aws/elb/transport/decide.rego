package policy.aws.flatt.elb.transport

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1beta",
		"kind": "aws_elb_transport",
		"subject": lb.metadata.id,
		"locator": "",
		"severity": shisho.decision.severity_high,
		"allowed": allow_if_excluded(allowed(lb), lb),
		"payload": json.marshal({
			"has_tls_listener": has_tls_listener(lb),
			"has_plaintext_listener": has_plaintext_listener(lb),
		}),
	})
}

allowed(lb) {
	not has_plaintext_listener(lb)
} else = false

has_tls_listener(lb) {
	lb.listeners[_].__typename == "AWSElasticLoadBalancerHTTPSListener"
} else {
	lb.listeners[_].__typename == "AWSElasticLoadBalancerTLSListener"
} else = false

has_plaintext_listener(lb) {
	lb.listeners[_].__typename == "AWSElasticLoadBalancerDefaultListener"
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
