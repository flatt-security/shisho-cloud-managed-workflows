package policy.googlecloud.compute.instance_ip_forwarding

import data.shisho
import future.keywords

test_whether_ip_forwarding_is_disabled_for_compute_engine_instance if {
	# check if the IP forwarding is disabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"canIpForward": false,
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903333"},
				"name": "yours",
				"canIpForward": false,
			},
		]},
	}]}}

	# check if the IP forwarding is enabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"canIpForward": false,
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"canIpForward": true,
			},
		]},
	}]}}
}
