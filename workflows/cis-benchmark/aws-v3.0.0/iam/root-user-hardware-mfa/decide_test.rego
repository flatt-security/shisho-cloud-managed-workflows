package policy.aws.iam.root_user_hardware_mfa

import data.shisho
import future.keywords

test_whether_the_hardware_mfa_device_is_enabled if {
	# check if the hardware MFA device is enabled
	# Allowed condition: no root owned virtual devices + mfaActive = true
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"id": "779392188153",
		"metadata": {"id": "aws-account|779392188153"},
		"iam": {
			"virtualMfaDevices": [{
				"serialNumber": "arn:aws:iam::779392188153:mfa/root-account-mfa-device",
				"user": {"arn": "arn:aws:iam::123456789012:user/JohnDoe"},
			}],
			"credentialReport": {"contents": [{
				"user": "<root_account>",
				"mfaActive": true,
				"arn": "arn:aws:iam::779392187777:root",
			}]},
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
			"virtualMfaDevices": [
				{"user": {"arn": "arn:aws:iam::123456789012:user/JohnDoe"}},
				{"user": null},
			],
			"credentialReport": {"contents": [{
				"user": "<root_account>",
				"mfaActive": false,
				"arn": "arn:aws:iam::779392188153:root",
			}]},
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
			"virtualMfaDevices": [
				{"user": {"arn": "arn:aws:iam::779392188153:root"}},
				{"user": null},
			],
			"credentialReport": {"contents": [{
				"user": "<root_account>",
				"mfaActive": true,
				"arn": "arn:aws:iam::779392188153:root",
			}]},
		},
	}]}}
}
