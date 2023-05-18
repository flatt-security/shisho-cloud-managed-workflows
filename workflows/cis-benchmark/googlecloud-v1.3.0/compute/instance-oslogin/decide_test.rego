package policy.googlecloud.compute.instance_oslogin

import data.shisho
import future.keywords

test_whether_os_login_is_enabled_for_compute_engine_instance if {
	# check if the OS login is enabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"instanceMetadata": {"items": [{
					"key": "enable-oslogin",
					"value": "TRUE",
				}]},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903333"},
				"name": "yours",
				"instanceMetadata": {"items": [{
					"key": "enable-oslogin",
					"value": "TRUE",
				}]},
			},
		]},
	}]}}

	# check if the OS login is enabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"instanceMetadata": {"items": [{
					"key": "enable-oslogin",
					"value": "FALSE",
				}]},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"instanceMetadata": {"items": [{
					"key": "enable-oslogin",
					"value": "TRUE",
				}]},
			},
		]},
	}]}}

	# check if the OS login is disabled for a Google Cloud Compute Engine instance
	# because the metadata items do not contain the key "enable-oslogin"
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"instanceMetadata": {"items": []},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"instanceMetadata": {"items": [{
					"key": "startup-script",
					"value": "test-script",
				}]},
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"instanceMetadata": {"items": [{
					"key": "cluster-location",
					"value": "asia-northeast1-a",
				}]},
			},
		]},
	}]}}
}
