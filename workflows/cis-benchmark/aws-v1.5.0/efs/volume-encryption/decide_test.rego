package policy.aws.efs.volume_encryption

import data.shisho
import future.keywords

test_whether_encryption_is_enabled_for_aws_efs_file_systems if {
	# check if the encryption is enabled for AWS EFS file systems
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf7777c"},
			"encrypted": true,
		},
		{
			"metadata": {"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf8888c"},
			"encrypted": true,
		},
		{
			"metadata": {"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf9999c"},
			"encrypted": true,
		},
	]}}]}}

	# check if all users is accessible for a Google Cloud BigQuery datasets
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"efs": {"fileSystems": [
		{
			"metadata": {"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf7777c"},
			"encrypted": false,
		},
		{
			"metadata": {"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf8888c"},
			"encrypted": false,
		},
		{
			"metadata": {"id": "aws-efs-filesystem|ap-northeast-1|fs-012583c95abf9999c"},
			"encrypted": true,
		},
	]}}]}}
}
