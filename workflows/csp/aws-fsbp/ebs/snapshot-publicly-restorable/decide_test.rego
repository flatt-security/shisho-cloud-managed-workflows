package policy.aws.ebs.snapshot_publicly_restorable

import data.shisho
import future.keywords

test_whether_ebs_snapshots_are_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{"ec2": {"snapshots": [{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"id": "snap-04b78a99547777777",
			"volumeId": "vol-03ff02b8d27777777",
			"attribute": {"createVolumePermissions": []},
		}]}},
		{"ec2": {"snapshots": [{
			"metadata": {
				"id": "aws-account|779397777778",
				"displayName": "779397777778",
			},
			"id": "snap-04b78a99547777778",
			"volumeId": "vol-03ff02b8d27777778",
			"attribute": {"createVolumePermissions": [{
				"group": "",
				"userId": "125527777778",
			}]},
		}]}},
	]}}
}

test_whether_ebs_snapshots_are_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{"ec2": {"snapshots": [{
			"metadata": {
				"id": "aws-account|779397777777",
				"displayName": "779397777777",
			},
			"id": "snap-04b78a99547777777",
			"volumeId": "vol-03ff02b8d27777777",
			"attribute": {"createVolumePermissions": [{
				"group": "ALL",
				"userId": "",
			}]},
		}]}},
		{"ec2": {"snapshots": [{
			"metadata": {
				"id": "aws-account|779397777778",
				"displayName": "779397777778",
			},
			"id": "snap-04b78a99547777778",
			"volumeId": "vol-03ff02b8d27777778",
			"attribute": {"createVolumePermissions": [{
				"group": "ALL",
				"userId": "",
			}]},
		}]}},
	]}}
}
