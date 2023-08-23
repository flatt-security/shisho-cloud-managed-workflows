package policy.aws.cloudfront.transport

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	behaviors := cache_behaviors(dist)
	allowed := includes_unallowed_behavior(behaviors)
	d := shisho.decision.aws.cloudfront.transport({
		"allowed": allow_if_excluded(allowed, dist),
		"subject": dist.metadata.id,
		"payload": shisho.decision.aws.cloudfront.transport_payload({"cache_behaviors": behaviors}),
	})
}

cache_behaviors(dist) = array.concat(
	[{
		"path_pattern": cb.pathPattern,
		"target_origin_id": cb.targetOriginId,
		"viewer_protocol_policy": cb.viewerProtocolPolicy,
	} |
		cb := dist.defaultCacheBehavior
	],
	[{
		"path_pattern": cb.pathPattern,
		"target_origin_id": cb.targetOriginId,
		"viewer_protocol_policy": cb.viewerProtocolPolicy,
	} |
		cb := dist.cacheBehaviors[_]
	],
)

includes_unallowed_behavior(behaviors) {
	b := behaviors[_]
	b.viewer_protocol_policy != "HTTPS_ONLY"
	b.viewer_protocol_policy != "REDIRECT_TO_HTTPS"
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
