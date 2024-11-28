package policy.aws.iam.root_user_key

import data.shisho
import future.keywords

test_whether_the_mfa_is_enabled_for_root_user if {
	# check if the MFA is enabled for the root user
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"accountSummary": {"summaryMap": [
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
				},
				{
					"key": "AccountSigningCertificatesPresent",
					"value": 0,
				},
				{
					"key": "UsersQuota",
					"value": 5000,
				},
				{
					"key": "PolicyVersionsInUse",
					"value": 21,
				},
				{
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "AccountAccessKeysPresent",
					"value": 0,
				},
				{
					"key": "Users",
					"value": 1,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 1,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
				},
				{
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "UserPolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "ServerCertificates",
					"value": 0,
				},
				{
					"key": "Roles",
					"value": 28,
				},
				{
					"key": "RolesQuota",
					"value": 1000,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "RolePolicySizeQuota",
					"value": 10240,
				},
				{
					"key": "InstanceProfilesQuota",
					"value": 1000,
				},
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
				{
					"key": "Providers",
					"value": 57,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
			]}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"accountSummary": {"summaryMap": [
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
				},
				{
					"key": "AccountSigningCertificatesPresent",
					"value": 0,
				},
				{
					"key": "UsersQuota",
					"value": 5000,
				},
				{
					"key": "PolicyVersionsInUse",
					"value": 21,
				},
				{
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "AccountAccessKeysPresent",
					"value": 0,
				},
				{
					"key": "Users",
					"value": 1,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 1,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
				},
				{
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "UserPolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "ServerCertificates",
					"value": 0,
				},
				{
					"key": "Roles",
					"value": 28,
				},
				{
					"key": "RolesQuota",
					"value": 1000,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "RolePolicySizeQuota",
					"value": 10240,
				},
				{
					"key": "InstanceProfilesQuota",
					"value": 1000,
				},
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
				{
					"key": "Providers",
					"value": 57,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
			]}},
		},
	]}}

	# check if the MFA is disbled for the root user
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"iam": {"accountSummary": {"summaryMap": [
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
				},
				{
					"key": "AccountSigningCertificatesPresent",
					"value": 0,
				},
				{
					"key": "UsersQuota",
					"value": 5000,
				},
				{
					"key": "PolicyVersionsInUse",
					"value": 21,
				},
				{
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "AccountAccessKeysPresent",
					"value": 1,
				},
				{
					"key": "Users",
					"value": 1,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 1,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
				},
				{
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "UserPolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "ServerCertificates",
					"value": 0,
				},
				{
					"key": "Roles",
					"value": 28,
				},
				{
					"key": "RolesQuota",
					"value": 1000,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "RolePolicySizeQuota",
					"value": 10240,
				},
				{
					"key": "InstanceProfilesQuota",
					"value": 1000,
				},
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
				{
					"key": "Providers",
					"value": 57,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
			]}},
		},
		{
			"metadata": {"id": "aws-account|779392188888"},
			"iam": {"accountSummary": {"summaryMap": [
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
				},
				{
					"key": "AccountSigningCertificatesPresent",
					"value": 0,
				},
				{
					"key": "UsersQuota",
					"value": 5000,
				},
				{
					"key": "PolicyVersionsInUse",
					"value": 21,
				},
				{
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "AccountAccessKeysPresent",
					"value": 1,
				},
				{
					"key": "Users",
					"value": 1,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 1,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
				},
				{
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "UserPolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "ServerCertificates",
					"value": 0,
				},
				{
					"key": "Roles",
					"value": 28,
				},
				{
					"key": "RolesQuota",
					"value": 1000,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "RolePolicySizeQuota",
					"value": 10240,
				},
				{
					"key": "InstanceProfilesQuota",
					"value": 1000,
				},
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
				{
					"key": "Providers",
					"value": 57,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
			]}},
		},
	]}}
}
