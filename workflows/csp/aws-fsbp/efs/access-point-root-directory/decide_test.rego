package policy.aws.efs.access_point_root_directory

import data.shisho
import future.keywords

test_whether_root_directory_is_not_pointed_for_aws_efs_access_points if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648c",
				"displayName": "test-efs-1",
			},
			"accessPoints": [{
				"id": "fsap-07c862c64ff884548",
				"rootDirectory": {"path": "/tmp/"},
			}],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648d",
				"displayName": "test-efs-3",
			},
			"accessPoints": [{
				"id": "fsap-07c862c64ff884549",
				"rootDirectory": {"path": "/sub/"},
			}],
		},
	]}}]}}
}

test_whether_root_directory_is_pointed_for_aws_efs_access_points if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-07d1242c69c10e68f",
				"displayName": "test-efs-2",
			},
			"accessPoints": [],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648c",
				"displayName": "test-efs-1",
			},
			"accessPoints": [{
				"id": "fsap-07c862c64ff884548",
				"rootDirectory": {"path": "/"},
			}],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648d",
				"displayName": "test-efs-3",
			},
			"accessPoints": [{
				"id": "fsap-07c862c64ff884549",
				"rootDirectory": {"path": "/"},
			}],
		},
	]}}]}}
}
