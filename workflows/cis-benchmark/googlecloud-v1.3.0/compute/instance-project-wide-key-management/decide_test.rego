package policy.googlecloud.compute.instance_project_wide_key_management

import data.shisho
import future.keywords

test_whether_proper_service_account_is_used_for_compute_engine_instance if {
	# check if users with project-wide SSH keys connecting to the Google Cloud Compute Engine instance are blocked
	# by the value "TRUE" of metadata "block-project-ssh-keys" 
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [{
		"metadata": {"id": "google-cloud-ce-instance|505096687472|asia-northeast1-a|9006941500481417662"},
		"instanceMetadata": {"items": [{
			"key": "block-project-ssh-keys",
			"value": "TRUE",
		}]},
	}]}}]}}

	# check if users with project-wide SSH keys connecting to the Google Cloud Compute Engine instance are blocked
	# by the value "true" of metadata "block-project-ssh-keys" 
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [{
		"metadata": {"id": "google-cloud-ce-instance|505096687472|asia-northeast1-a|9006941500481417662"},
		"instanceMetadata": {"items": [{
			"key": "block-project-ssh-keys",
			"value": "true",
		}]},
	}]}}]}}

	# check if users with project-wide SSH keys connecting to the Google Cloud Compute Engine instance are not blocked
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [{
		"metadata": {"id": "google-cloud-ce-instance|505096687472|asia-northeast1-a|9006941500481417662"},
		"instanceMetadata": {"items": [{
			"key": "block-project-ssh-keys",
			"value": "false",
		}]},
	}]}}]}}
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
		shisho.decision.has_severity(d, shisho.decision.severity_medium)
	]) == 1 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [{
		"metadata": {"id": "google-cloud-ce-instance|505096687472|asia-northeast1-a|9006941500481417662"},
		"instanceMetadata": {"items": [
			{
				"key": "block-project-ssh-keys",
				"value": "false",
			},
			{
				"key": "ssh-keys",
				"value": "ssh-gegehoge",
			},
		]},
	}]}}]}}

	# check if the metadata does not contain the metadata item about the configuraiton of "project-wide SSH keys"
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [{
		"metadata": {"id": "google-cloud-ce-instance|505096687472|asia-northeast1-a|9006941500481417662"},
		"instanceMetadata": {"items": [{
			"key": "metadata-key",
			"value": "true",
		}]},
	}]}}]}}

	# check if the metadata items are empty
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"googleCloud": {"projects": [{"computeEngine": {"instances": [{
		"metadata": {"id": "google-cloud-ce-instance|505096687472|asia-northeast1-a|9006941500481417662"},
		"instanceMetadata": {"items": []},
	}]}}]}}
}
