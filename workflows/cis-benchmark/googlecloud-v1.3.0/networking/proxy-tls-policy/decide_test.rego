package policy.googlecloud.networking.proxy_tls_policy

import data.shisho
import future.keywords

test_whether_tls_configuration_is_secured_for_ssl_policies if {
	# check if the TLS configurations are secured for SSL policies
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {
				"targetHttpsProxies": [],
				"targetSslProxies": [],
				"sslPolicies": [
					{
						"metadata": {"id": "googlecloud-nw-ssl-policy|514893244444|56522586120412345"},
						"minimumTlsVersion": "TLS_1_0",
						"profile": "RESTRICTED",
						"enabledFeatures": [],
						"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/sslPolicies/56522586120212346",
					},
					{
						"metadata": {"id": "googlecloud-nw-ssl-policy|514893244444|56522586120412346"},
						"minimumTlsVersion": "TLS_1_2",
						"profile": "MODERN",
						"enabledFeatures": [],
						"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/sslPolicies/56522586120412346",
					},
				],
			},
		},
		{
			"id": "test-project-2",
			"network": {
				"targetHttpsProxies": [],
				"targetSslProxies": [],
				"sslPolicies": [{
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
					"minimumTlsVersion": "TLS_1_2",
					"profile": "MODERN",
					"enabledFeatures": [],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
				}],
			},
		},
	]}}

	# check if the TLS configurations are secured for SSL policies
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.has_severity(d, shisho.decision.severity_low)
	]) == 3 with input as {"googleCloud": {"projects": [
		{
			"id": "test-project-1",
			"network": {
				"targetHttpsProxies": [],
				"targetSslProxies": [],
				"sslPolicies": [{
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893244444|56522586120412346"},
					"minimumTlsVersion": "TLS_1_0", # TLS should be at least TLS_1_2
					"profile": "MODERN",
					"enabledFeatures": [],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-1/global/sslPolicies/56522586120412346",
				}],
			},
		},
		{
			"id": "test-project-2",
			"network": {
				"targetHttpsProxies": [],
				"targetSslProxies": [],
				"sslPolicies": [
					{
						"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
						"minimumTlsVersion": "TLS_1_2",
						"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
						"enabledFeatures": [],
						"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
					},
					{
						"metadata": {"id": "googlecloud-nw-ssl-policy|514893244444|56522586120418888"},
						"minimumTlsVersion": "TLS_1_2",
						"profile": "CUSTOM",
						"enabledFeatures": [
							"TLS_RSA_WITH_AES_128_GCM_SHA256", # `enabledFeatures` should not contain the features
							"TLS_RSA_WITH_AES_256_GCM_SHA384",
						],
						"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120418888",
					},
				],
			},
		},
	]}}

	# When the real HTTPS proxy is insecure, the decision should have higher severity.
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.severity_low < d.header.severity
	]) == 1 with input as {"googleCloud": {"projects": [{
		"id": "test-project-2",
		"network": {
			"targetHttpsProxies": [{
				"metadata": {"id": "googlecloud-nw-hoge|514893255555|56522586120417777"},
				"sslPolicy": {
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
					"minimumTlsVersion": "TLS_1_2",
					"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
					"enabledFeatures": [],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
				},
			}],
			"targetSslProxies": [],
			"sslPolicies": [{
				"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
				"minimumTlsVersion": "TLS_1_2",
				"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
				"enabledFeatures": [],
				"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
			}],
		},
	}]}}

	# The decisions should be created even if there are used and unused SSL policies.
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"id": "test-project-2",
		"network": {
			"targetHttpsProxies": [{
				"metadata": {"id": "googlecloud-nw-hoge|514893255555|56522586120417777"},
				"sslPolicy": {
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
					"minimumTlsVersion": "TLS_1_2",
					"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
					"enabledFeatures": [],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
				},
			}],
			"targetSslProxies": [],
			"sslPolicies": [
				{
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
					"minimumTlsVersion": "TLS_1_2",
					"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
					"enabledFeatures": [],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
				},
				{
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893244444|56522586120418888"},
					"minimumTlsVersion": "TLS_1_2",
					"profile": "CUSTOM",
					"enabledFeatures": [
						"TLS_RSA_WITH_AES_128_GCM_SHA256", # `enabledFeatures` should not contain the features
						"TLS_RSA_WITH_AES_256_GCM_SHA384",
					],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120418888",
				},
			],
		},
	}]}}

	# When the real TLS proxy is insecure, the decision should have higher severity.
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.severity_low < d.header.severity
	]) == 1 with input as {"googleCloud": {"projects": [{
		"id": "test-project-2",
		"network": {
			"targetHttpsProxies": [],
			"targetSslProxies": [{
				"metadata": {"id": "googlecloud-nw-hoge|514893255555|56522586120417777"},
				"sslPolicy": {
					"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
					"minimumTlsVersion": "TLS_1_2",
					"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
					"enabledFeatures": [],
					"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
				},
			}],
			"sslPolicies": [{
				"metadata": {"id": "googlecloud-nw-ssl-policy|514893255555|56522586120417777"},
				"minimumTlsVersion": "TLS_1_2",
				"profile": "COMPATIBLE", # profile should be either MODERN, RESTRICTED or CUSTOM
				"enabledFeatures": [],
				"selfLink": "https://www.googleapis.com/compute/v1/projects/test-project-2/global/sslPolicies/56522586120417777",
			}],
		},
	}]}}
}
