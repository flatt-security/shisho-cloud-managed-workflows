package policy.aws.cloudfront.origin_transport

import data.shisho

###########################
# origin_transport
###########################

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	origins := origin_transports(dist)
	allowed := includes_unallowed_origin_transport(dist, origins) == false
	d := shisho.decision.aws.cloudfront.origin_transport({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.origin_transport_payload({"origins": origins}),
	})
}

viewer_can_use_http(dist) {
	cb := dist.cacheBehaviors[_]
	cb.viewerProtocolPolicy == "ALLOW_ALL"
} else {
	cb := dist.defaultCacheBehavior
	cb.viewerProtocolPolicy == "ALLOW_ALL"
} else := false

origin_transports(dist) = [{
	"id": o.id,
	"domain_name": o.domainName,
	"protocol_policy": o.backend.protocolPolicy,
	"ssl_protocols": o.backend.sslProtocols,
} |
	o := dist.origins[_]
	o.backend != null
	o.backend.protocolPolicy != null
	o.backend.sslProtocols != null
]

includes_unallowed_origin_transport(dist, origins) {
	o := origins[_]
	o.protocol_policy == "HTTP_ONLY"
} else {
	o := origins[_]
	o.protocol_policy == "MATCH_VIEWER"
	viewer_can_use_http(dist)
} else := false

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

###########################
# origin_transport_version
###########################

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	origins := origin_transports(dist)
	allowed := includes_unallowed_origin_transport_version(dist, origins) == false
	d := shisho.decision.aws.cloudfront.origin_transport_version({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.origin_transport_version_payload({"origins": origins}),
	})
}

includes_unallowed_origin_transport_version(dist, origins) {
	o := origins[_]
	includes_sslv3(o)
} else := false

includes_sslv3(o) {
	p := o.ssl_protocols[_]
	p == "SSLV3"
} else := false
