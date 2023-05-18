package policy.googlecloud.compute.instance_service_account

import data.shisho
import future.keywords

test_whether_proper_service_account_is_used_for_compute_engine_instance if {
	# check if the default service account is not used for a Google Cloud Compute Engine instance
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
				"name": "pod",
				"serviceAccount": {"email": "test-account-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"serviceAccount": {"email": "test-account-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229904444"},
				"name": "bunch",
				"serviceAccount": {"email": "test-account-compute@developer.gserviceaccount.com"},
				"labels": [],
			},
		]},
	}]}}

	# check if the default service account is used for a Google Compute Engine instance
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
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "bunch",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "test-value",
				}],
			},
		]},
	}]}}

	# check if the default service account is used for a Google Cloud Compute Engine instance
	# but the instance name starts with `gke-` and it is labeled as `goog-gke-node`
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
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
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "gke-bunch",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "goog-gke-node",
				}],
			},
		]},
	}]}}

	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
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
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "gke-bunch",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "goog-gke-node",
				}],
			},
		]},
	}]}}
		with data.params as {"excludes_gke_nodes": false}
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{
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
			},
			{
				"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
				"name": "gke-bunch",
				"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
				"labels": [{
					"key": "test-key",
					"value": "goog-gke-node",
				}],
			},
		]},
	}]}}
		with data.params as {"excludes_gke_nodes": true}

	# check if the default service account is used for a Google Cloud Compute Engine instance
	# and the instance name does not stars with `gke-`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [{
			"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|8881795636229903417"},
			"name": "bunch",
			"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
			"labels": [{
				"key": "test-key",
				"value": "goog-gke-node",
			}],
		}]},
	}]}}

	# check if the default service account is used for a Google Cloud Compute Engine instance
	# and it is not labeled as `goog-gke-node`
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{
		"number": 354711641168,
		"computeEngine": {"instances": [{
			"metadata": {"id": "google-cloud-ce-instance|354711641168|asia-northeast2-a|7816137240199088770"},
			"name": "gke-pod",
			"serviceAccount": {"email": "354711641168-compute@developer.gserviceaccount.com"},
			"labels": [{
				"key": "test-key",
				"value": "test-value",
			}],
		}]},
	}]}}
}
