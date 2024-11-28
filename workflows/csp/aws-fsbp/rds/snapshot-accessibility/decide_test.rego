package policy.aws.rds.snapshot_accessibility

import data.shisho
import future.keywords

test_public_accessibility_of_rds_databases_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 6 with input as {"aws": {"accounts": [{"rds": {
		"instances": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
					"displayName": "docdb-2023-06-28-12-28-51",
				},
				"engine": "DOCDB",
				"snapshots": [{
					"id": "rds:test-mysql-1-2023-06-28-10-55",
					"attributes": [{
						"name": "restore",
						"values": [],
					}],
				}],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
					"displayName": "test-aurora-mysql-1-instance-1",
				},
				"engine": "AURORA_MYSQL",
				"snapshots": [{
					"id": "rds:test-mysql-1-2023-06-28-10-55",
					"attributes": [{
						"name": "restore",
						"values": [],
					}],
				}],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
					"displayName": "test-mysql-1",
				},
				"engine": "MYSQL",
				"snapshots": [
					{
						"id": "rds:test-mysql-1-2023-06-28-10-55",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
					{
						"id": "rds:test-mysql-1-2023-06-28-18-22",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
					{
						"id": "test-mysql-snapshot-1",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
				],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1-instance-1",
					"displayName": "test-neptune-cluster-1-instance-1",
				},
				"engine": "NEPTUNE",
				"snapshots": [],
			},
		],
		"clusters": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
					"displayName": "docdb-2023-06-28-12-28-51",
				},
				"engine": "docdb",
				"snapshots": [
					{
						"id": "etst-docdb-snapshot-1",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
					{
						"id": "rds:docdb-2023-06-28-12-28-51-2023-06-29-00-01",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
				],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1",
					"displayName": "test-aurora-mysql-1",
				},
				"engine": "aurora-mysql",
				"snapshots": [
					{
						"id": "etst-aurora-mysql-snapshot-1",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
					{
						"id": "rds:test-aurora-mysql-1-2023-06-28-15-26",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
				],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1",
					"displayName": "test-neptune-cluster-1",
				},
				"engine": "neptune",
				"snapshots": [
					{
						"id": "rds:test-neptune-cluster-1-2023-06-28-15-15",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
					{
						"id": "test-nepture-cluster-snapshot-1",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
				],
			},
		],
	}}]}}
}

test_public_accessibility_of_rds_databases_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 4 with input as {"aws": {"accounts": [{"rds": {
		"instances": [
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
					"displayName": "docdb-2023-06-28-12-28-51",
				},
				"engine": "DOCDB",
				"snapshots": [{
					"id": "rds:test-mysql-1-2023-06-28-10-55",
					"attributes": [{
						"name": "restore",
						"values": ["all"],
					}],
				}],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
					"displayName": "test-aurora-mysql-1-instance-1",
				},
				"engine": "AURORA_MYSQL",
				"snapshots": [{
					"id": "rds:test-mysql-1-2023-06-28-10-55",
					"attributes": [{
						"name": "restore",
						"values": ["all"],
					}],
				}],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
					"displayName": "test-mysql-1",
				},
				"engine": "MYSQL",
				"snapshots": [
					{
						"id": "rds:test-mysql-1-2023-06-28-10-55",
						"attributes": [{
							"name": "restore",
							"values": ["all"],
						}],
					},
					{
						"id": "rds:test-mysql-1-2023-06-28-18-22",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
					{
						"id": "test-mysql-snapshot-1",
						"attributes": [{
							"name": "restore",
							"values": [],
						}],
					},
				],
			},
			{
				"metadata": {
					"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1-instance-1",
					"displayName": "test-neptune-cluster-1-instance-1",
				},
				"engine": "NEPTUNE",
				"snapshots": [],
			},
		],
		"clusters": [{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"engine": "docdb",
			"snapshots": [
				{
					"id": "etst-docdb-snapshot-1",
					"attributes": [{
						"name": "restore",
						"values": ["all"],
					}],
				},
				{
					"id": "rds:docdb-2023-06-28-12-28-51-2023-06-29-00-01",
					"attributes": [{
						"name": "restore",
						"values": [],
					}],
				},
			],
		}],
	}}]}}
}
