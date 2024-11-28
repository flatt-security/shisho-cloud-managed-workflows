package policy.aws.efs.volume_backup_plan

import data.shisho
import future.keywords

test_whether_backup_plan_is_enabled_for_aws_efs_file_systems if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-07d1242c69c10e68f",
				"displayName": "test-efs-2",
			},
			"backupPolicy": {"status": "ENABLED"},
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648c",
				"displayName": "test-efs-1",
			},
			"backupPolicy": {"status": "ENABLED"},
		},
	]}}]}}
}

test_whether_backup_plan_is_not_enabled_for_aws_efs_file_systems if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-07d1242c69c10e68f",
				"displayName": "test-efs-2",
			},
			"backupPolicy": {"status": "DISABLING"},
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648c",
				"displayName": "test-efs-1",
			},
			"backupPolicy": {"status": "DISABLED"},
		},
	]}}]}}
}
