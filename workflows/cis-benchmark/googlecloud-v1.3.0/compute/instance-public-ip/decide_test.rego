package policy.googlecloud.compute.instance_public_ip

import data.shisho
import future.keywords

test_whether_pulic_ip_addresses_are_not_used_for_compute_engine_instance if {
	# check if the public IP addresses are not used for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
				"networkInterfaces": [
					{"ipv4AccessConfig": {
						"name": "external-nat",
						"natIp": null,
					}},
					{"ipv4AccessConfig": {
						"name": "external-nat",
						"natIp": "",
					}},
				],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903333"},
				"name": "yours",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
				"networkInterfaces": [{"ipv4AccessConfig": {
					"name": "external-nat",
					"natIp": "",
				}}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229904444"},
				"name": "yours",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [],
				"networkInterfaces": [{"ipv4AccessConfig": {
					"name": "external-nat",
					"natIp": "",
				}}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229905555"},
				"name": "yours",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
				"networkInterfaces": [],
			},
		]},
	}]}}

	# check if the public IP addresses is used for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
				"networkInterfaces": [
					{"ipv4AccessConfig": {
						"name": "External NAT",
						"natIp": "130.212.121.55",
					}},
					{"ipv4AccessConfig": {
						"name": "External NAT11",
						"natIp": "130.212.121.56",
					}},
				],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
				"networkInterfaces": [
					{"ipv4AccessConfig": {
						"name": "External NAT",
						"natIp": "130.212.121.55",
					}},
					{"ipv4AccessConfig": {
						"name": "External NAT11",
						"natIp": "130.212.121.56",
					}},
				],
			},
		]},
	}]}}

	# check if the public IP addresses are bypassed for a Google Cloud Compute Engine instance
	# because it is not labeled as `goog-gke-node`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "gke-pod",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "goog-gke-node",
				}],
				"networkInterfaces": [
					{"ipv4AccessConfig": {
						"name": "External NAT",
						"natIp": "130.212.121.55",
					}},
					{"ipv4AccessConfig": {
						"name": "External NAT11",
						"natIp": "130.212.121.56",
					}},
				],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
				"networkInterfaces": [
					{"ipv4AccessConfig": {
						"name": "External NAT",
						"natIp": "130.212.121.55",
					}},
					{"ipv4AccessConfig": {
						"name": "External NAT11",
						"natIp": "130.212.121.56",
					}},
				],
			},
		]},
	}]}}
}
