package policy.aws.networking.acl_assosiations

import data.shisho
import future.keywords

test_whether_acl_assosiations_of_vpcs_is_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"metadata": {
				"id": "aws-vpc|ap-northeast-2|vpc-0f31afb45624b35c7",
				"displayName": "vpc-0f31afb45624b35c7",
			},
			"acls": [{
				"id": "acl-0b927538857e52978",
				"associations": [
					{"id": "aclassoc-02f52a3ce45425673"},
					{"id": "aclassoc-03e6117c8baf61845"},
					{"id": "aclassoc-064a5bcbcc2ba398c"},
					{"id": "aclassoc-0085df8f0dd772a39"},
				],
			}],
		},
		{
			"metadata": {
				"id": "aws-vpc|ap-southeast-2|vpc-08b371f928bae1fbe",
				"displayName": "vpc-08b371f928bae1fbe",
			},
			"acls": [{
				"id": "acl-08d5b0f851fc4a9b9",
				"associations": [
					{"id": "aclassoc-0b7603e232d2d6148"},
					{"id": "aclassoc-04497bdc9bb823bf6"},
					{"id": "aclassoc-0ed9a491df66287b1"},
				],
			}],
		},
		{
			"metadata": {
				"id": "aws-vpc|us-west-1|vpc-0c7dd99f9cf0199b0",
				"displayName": "vpc-0c7dd99f9cf0199b0",
			},
			"acls": [{
				"id": "acl-02ddc44fa0c762957",
				"associations": [{"id": "aclassoc-0b7603e232d2d6148"}],
			}],
		},
	]}}]}}
}

test_whether_acl_assosiations_of_vpcs_is_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"network": {"vpcs": [
		{
			"metadata": {
				"id": "aws-vpc|ap-southeast-2|vpc-08b371f928bae1fbe",
				"displayName": "vpc-08b371f928bae1fbe",
			},
			"acls": [{
				"id": "acl-08d5b0f851fc4a9b9",
				"associations": [],
			}],
		},
		{
			"metadata": {
				"id": "aws-vpc|us-west-1|vpc-0c7dd99f9cf0199b0",
				"displayName": "vpc-0c7dd99f9cf0199b0",
			},
			"acls": [{
				"id": "acl-02ddc44fa0c762957",
				"associations": [],
			}],
		},
	]}}]}}
}
