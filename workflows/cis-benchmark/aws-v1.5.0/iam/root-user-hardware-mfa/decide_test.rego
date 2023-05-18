package policy.aws.iam.root_user_hardware_mfa

import data.shisho
import future.keywords

test_whether_the_hardware_mfa_device_is_enabled if {
	# check if the hardware MFA device is enabled
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"id": "779392188153",
		"metadata": {"id": "aws-account|779392188153"},
		"iam": {
			"accountSummary": {"summaryMap": [
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
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
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 1,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
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
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
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
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
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
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "AccountSigningCertificatesPresent",
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
					"key": "Providers",
					"value": 59,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
			]},
			"virtualMfaDevices": [
				{"serialNumber": "arn:aws:iam::779392188153:mfa/iPhone"},
				{"serialNumber": "arn:aws:iam::779392188153:mfa/test-mfa-device"},
			],
		},
	}]}}

	# check if the hardware MFA device is disabled
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"id": "779392188153",
		"metadata": {"id": "aws-account|779392188153"},
		"iam": {
			"accountSummary": {"summaryMap": [
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
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
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 0,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
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
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
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
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
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
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "AccountSigningCertificatesPresent",
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
					"key": "Providers",
					"value": 59,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
			]},
			"virtualMfaDevices": [
				{"serialNumber": "arn:aws:iam::779392188153:mfa/root-account-mfa-device"},
				{"serialNumber": "arn:aws:iam::779392188153:mfa/test-mfa-device"},
			],
		},
	}]}}

	# check if the MFA device is enabled but the device is the virtual MFA device
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"id": "779392188153",
		"metadata": {"id": "aws-account|779392188153"},
		"iam": {
			"accountSummary": {"summaryMap": [
				{
					"key": "InstanceProfiles",
					"value": 2,
				},
				{
					"key": "AttachedPoliciesPerGroupQuota",
					"value": 10,
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
					"key": "AttachedPoliciesPerRoleQuota",
					"value": 10,
				},
				{
					"key": "PolicySizeQuota",
					"value": 6144,
				},
				{
					"key": "Groups",
					"value": 0,
				},
				{
					"key": "GroupsQuota",
					"value": 300,
				},
				{
					"key": "GroupsPerUserQuota",
					"value": 10,
				},
				{
					"key": "AttachedPoliciesPerUserQuota",
					"value": 10,
				},
				{
					"key": "AccountMFAEnabled",
					"value": 1,
				},
				{
					"key": "AccessKeysPerUserQuota",
					"value": 2,
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
					"key": "PolicyVersionsInUseQuota",
					"value": 10000,
				},
				{
					"key": "VersionsPerPolicyQuota",
					"value": 5,
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
					"key": "MFADevicesInUse",
					"value": 1,
				},
				{
					"key": "GroupPolicySizeQuota",
					"value": 5120,
				},
				{
					"key": "Policies",
					"value": 0,
				},
				{
					"key": "AssumeRolePolicySizeQuota",
					"value": 2048,
				},
				{
					"key": "MFADevices",
					"value": 2,
				},
				{
					"key": "SigningCertificatesPerUserQuota",
					"value": 2,
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
					"key": "GlobalEndpointTokenVersion",
					"value": 1,
				},
				{
					"key": "AccountSigningCertificatesPresent",
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
					"key": "Providers",
					"value": 59,
				},
				{
					"key": "ServerCertificatesQuota",
					"value": 20,
				},
				{
					"key": "PoliciesQuota",
					"value": 1500,
				},
			]},
			"virtualMfaDevices": [
				{"serialNumber": "arn:aws:iam::779392188153:mfa/root-account-mfa-device"},
				{"serialNumber": "arn:aws:iam::779392188153:mfa/test-mfa-device"},
			],
		},
	}]}}
}
