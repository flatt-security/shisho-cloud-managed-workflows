package policy.aws.cloudfront.transport

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	dist := account.cloudFront.distributions[_]

	behaviors := cache_behaviors(dist)
	allowed := includes_unallowed_behavior(behaviors)
	d := shisho.decision.aws.cloudfront.transport({
		"allowed": allowed,
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
