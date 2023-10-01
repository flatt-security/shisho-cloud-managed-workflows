package policy.googlecloud.compute.instance_serial_port

import data.shisho
import future.keywords

test_whether_serial_port_is_disabled_for_compute_engine_instance if {
	# check if the serial port is disabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {
			"projectMetadata": {"items": []},
			"instances": [
				{
					"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
					"name": "pod",
					"instanceMetadata": {"items": [{
						"key": "serial-port-enable",
						"value": "false",
					}]},
				},
				{
					"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903333"},
					"name": "yours",
					"instanceMetadata": {"items": [{
						"key": "serial-port-enable",
						"value": "0",
					}]},
				},
			],
		},
	}]}}

	# check if the serial port is enabled for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {
			"projectMetadata": {"items": []},
			"instances": [
				{
					"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
					"name": "pod",
					"instanceMetadata": {"items": [{
						"key": "serial-port-enable",
						"value": "false",
					}]},
				},
				{
					"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
					"name": "bunch",
					"instanceMetadata": {"items": [{
						"key": "serial-port-enable",
						"value": "TRUE",
					}]},
				},
			],
		},
	}]}}

	# check if the serial port is disable for a Google Cloud Compute Engine instance
	# because the metadata items do not contain the key "enable-oslogin"
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {
			"projectMetadata": {"items": []},
			"instances": [
				{
					"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
					"name": "pod",
					"instanceMetadata": {"items": []},
				},
				{
					"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
					"name": "bunch",
					"instanceMetadata": {"items": [{
						"key": "startup-script",
						"value": "test-script",
					}]},
				},
			],
		},
	}]}}
}
