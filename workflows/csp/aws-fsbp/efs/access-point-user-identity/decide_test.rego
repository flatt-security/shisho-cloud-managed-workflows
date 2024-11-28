package policy.aws.efs.access_point_user_identity

import data.shisho
import future.keywords

test_whether_user_identity_is_configured_for_aws_efs_access_points if {
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
				"posixUser": {
					"uid": 3,
					"gid": 12,
				},
			}],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648d",
				"displayName": "test-efs-3",
			},
			"accessPoints": [{
				"id": "fsap-07c862c64ff884549",
				"posixUser": {
					"uid": 1,
					"gid": 12,
				},
			}],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648f",
				"displayName": "test-efs-4",
			},
			"accessPoints": [],
		},
	]}}]}}
}

test_whether_user_identity_is_not_configured_for_aws_efs_access_points if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-07d1242c69c10e68f",
				"displayName": "test-efs-2",
			},
			"accessPoints": [{
				"id": "fsap-01691afa05df9d066",
				"posixUser": null,
			}],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648c",
				"displayName": "test-efs-1",
			},
			"accessPoints": [{
				"id": "fsap-07c862c64ff884548",
				"posixUser": null,
			}],
		},
		{
			"metadata": {
				"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf1648f",
				"displayName": "test-efs-4",
			},
			"accessPoints": [],
		},
	]}}]}}
}
