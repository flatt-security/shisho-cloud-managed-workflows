package policy.googlecloud.compute.instance_shielded_vm

import data.shisho
import future.keywords

test_whether_shielded_vm_is_enabled_for_compute_engine_instance if {
	# check if the shielded VM is enabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"shieldedInstanceConfiguration": {
					"enableIntegrityMonitoring": true,
					"enableSecureBoot": true,
					"enableVtpm": true,
				},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903333"},
				"name": "yours",
				"shieldedInstanceConfiguration": {
					"enableIntegrityMonitoring": true,
					"enableSecureBoot": true,
					"enableVtpm": true,
				},
			},
		]},
	}]}}

	# check if the shielded VM is disabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"shieldedInstanceConfiguration": {
					"enableIntegrityMonitoring": false,
					"enableSecureBoot": false,
					"enableVtpm": false,
				},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"shieldedInstanceConfiguration": {
					"enableIntegrityMonitoring": false,
					"enableSecureBoot": false,
					"enableVtpm": false,
				},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229902417"},
				"name": "aaaaa",
				"shieldedInstanceConfiguration": null,
			},
		]},
	}]}}
}
