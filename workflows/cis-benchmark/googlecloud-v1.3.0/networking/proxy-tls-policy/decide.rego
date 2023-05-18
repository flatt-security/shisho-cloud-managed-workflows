package policy.googlecloud.networking.proxy_tls_policy

import data.shisho

# Reports insecure TLS policies used by target HTTPS proxies.
decisions[d] {
	project := input.googleCloud.projects[_]
	proxy := project.network.targetHttpsProxies[_]

	allowed := uses_secure_tls_policy(proxy.sslPolicy)
	d := shisho.decision.googlecloud.networking.proxy_tls_policy({
		"allowed": allowed,
		"subject": proxy.metadata.id,
		"payload": shisho.decision.googlecloud.networking.proxy_tls_policy_payload({"tls_policy_attached": proxy.sslPolicy != null}),
	})
}

# Reports insecure TLS policies used by target SSL proxies.
decisions[d] {
	project := input.googleCloud.projects[_]
	proxy := project.network.targetSslProxies[_]

	allowed := uses_secure_tls_policy(proxy.sslPolicy)
	d := shisho.decision.googlecloud.networking.proxy_tls_policy({
		"allowed": allowed,
		"subject": proxy.metadata.id,
		"payload": shisho.decision.googlecloud.networking.proxy_tls_policy_payload({"tls_policy_attached": proxy.sslPolicy != null}),
	})
}

used_policy_self_links := union({
	{proxy.sslPolicy.selfLink |
		p := input.googleCloud.projects[_]
		proxy := p.network.targetHttpsProxies[_]
		proxy.sslPolicy != null
	},
	{proxy.sslPolicy.selfLink |
		p := input.googleCloud.projects[_]
		proxy := p.network.targetSslProxies[_]
		proxy.sslPolicy != null
	},
})

# Reports unused and insecure TLS policies.
decisions[d] {
	project := input.googleCloud.projects[_]
	policy := project.network.sslPolicies[_]
	not used_policy_self_links[policy.selfLink]

	allowed := uses_secure_tls_policy(policy)
	d := shisho.decision.googlecloud.networking.proxy_tls_policy({
		"allowed": allowed,
		"subject": policy.metadata.id,
		"payload": shisho.decision.googlecloud.networking.proxy_tls_policy_payload({"tls_policy_attached": false}),
		# Levels down the severity because just a fact this SSL policy exists is not a direct security risk.
		"severity": shisho.decision.severity_low,
	})
}

uses_secure_tls_policy(policy) {
	policy != null
	policy.profile == "RESTRICTED"
} else {
	policy != null
	policy.profile == "MODERN"
	policy.minimumTlsVersion == "TLS_1_2"
} else {
	policy != null
	policy.profile == "CUSTOM"
	not has_feature(policy.enabledFeatures, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256")
	not has_feature(policy.enabledFeatures, "TLS_RSA_WITH_AES_128_GCM_SHA256")
	not has_feature(policy.enabledFeatures, "TLS_RSA_WITH_AES_256_GCM_SHA384")
	not has_feature(policy.enabledFeatures, "TLS_RSA_WITH_AES_128_CBC_SHA")
	not has_feature(policy.enabledFeatures, "TLS_RSA_WITH_AES_256_CBC_SHA")
	not has_feature(policy.enabledFeatures, "TLS_RSA_WITH_3DES_EDE_CBC_SHA")
} else = false {
	true
}

has_feature(features, feature) {
	features[_] == feature
} else = false {
	true
}
