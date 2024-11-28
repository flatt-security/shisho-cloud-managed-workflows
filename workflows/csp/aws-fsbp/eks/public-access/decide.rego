package policy.aws.eks.public_access

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	cluster := account.eks.clusters[_]

	allowed := is_public_endpoint_accessible(cluster) == false
	d := shisho.decision.aws.eks.public_access({
		"allowed": allow_if_excluded(allowed, cluster),
		"subject": cluster.metadata.id,
		"payload": shisho.decision.aws.eks.public_access_payload({
			"public_access_denied": cluster.resourcesVpcConfiguration.endpointPublicAccess == false,
			"allowed_cidr_blocks": cluster.resourcesVpcConfiguration.publicAccessCidrs,
		}),
	})
}

is_public_endpoint_accessible(cluster) {
	cluster.resourcesVpcConfiguration.endpointPublicAccess
} else {
	cluster.resourcesVpcConfiguration.publicAccessCidrs[_] == "0.0.0.0/0"
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
