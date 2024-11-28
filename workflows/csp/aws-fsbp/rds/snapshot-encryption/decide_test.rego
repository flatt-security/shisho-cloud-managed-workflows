package policy.aws.rds.snapshot_encryption

import data.shisho
import future.keywords

test_encryption_of_rds_databases_will_be_allowed if {
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
					"encrypted": true,
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
					"encrypted": true,
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
						"encrypted": true,
					},
					{
						"id": "rds:test-mysql-1-2023-06-28-18-22",
						"encrypted": true,
					},
					{
						"id": "test-mysql-snapshot-1",
						"encrypted": true,
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
						"storageEncrypted": true,
					},
					{
						"id": "rds:docdb-2023-06-28-12-28-51-2023-06-29-00-01",
						"storageEncrypted": true,
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
						"storageEncrypted": true,
					},
					{
						"id": "rds:test-aurora-mysql-1-2023-06-28-15-26",
						"storageEncrypted": true,
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
						"storageEncrypted": true,
					},
					{
						"id": "test-nepture-cluster-snapshot-1",
						"storageEncrypted": true,
					},
				],
			},
		],
	}}]}}
}

test_encryption_of_rds_databases_will_be_denied if {
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
					"encrypted": false,
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
					"encrypted": false,
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
						"encrypted": true,
					},
					{
						"id": "rds:test-mysql-1-2023-06-28-18-22",
						"encrypted": false,
					},
					{
						"id": "test-mysql-snapshot-1",
						"encrypted": false,
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
					"storageEncrypted": true,
				},
				{
					"id": "rds:docdb-2023-06-28-12-28-51-2023-06-29-00-01",
					"storageEncrypted": false,
				},
			],
		}],
	}}]}}
}
