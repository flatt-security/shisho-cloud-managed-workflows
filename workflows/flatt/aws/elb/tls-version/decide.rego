package policy.aws.flatt.elb.tls_version

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	# If the lb doesn't have any TLS listener, then it's not possible to have a minimum protocol version.
	# Ignore them.
	has_tls_listener(lb)

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1beta",
		"kind": "aws_elb_tls_version",
		"subject": lb.metadata.id,
		"locator": "",
		"severity": shisho.decision.severity_high,
		"allowed": allow_if_excluded(has_unacceptable_minimum_version(lb) == false, lb),
		"payload": json.marshal({"tls_versions": tls_policies(lb)}),
	})
}

has_tls_listener(lb) {
	lb.listeners[_].__typename == "AWSElasticLoadBalancerHTTPSListener"
} else {
	lb.listeners[_].__typename == "AWSElasticLoadBalancerTLSListener"
} else = false

has_unacceptable_minimum_version(lb) {
	p := tls_policies(lb)[_]
	p.tls_policy == unacceptable_tls_policy[_]
} else = false

unacceptable_tls_policy = [
	"ELBSecurityPolicy-2015-05",
	"ELBSecurityPolicy-2016-08",
	"ELBSecurityPolicy-TLS-1-1-2017-01",
	"ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
	"ELBSecurityPolicy-FS-2018-06",
	"ELBSecurityPolicy-FS-1-1-2019-08",
	"ELBSecurityPolicy-FS-1-2-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2019-08",
	"ELBSecurityPolicy-FS-1-2-Res-2020-10",
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
	"ELBSecurityPolicy-TLS13-1-1-2021-06",
	"ELBSecurityPolicy-TLS13-1-0-2021-06",
	"ELBSecurityPolicy-TLS13-1-3-2021-06",
]

tls_policies(lb) := [{
	"listener_arn": l.arn,
	"tls_policy": l.sslPolicy,
} |
	l := lb.listeners[_]
] {
	count(lb.listeners) > 0
} else := []

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
