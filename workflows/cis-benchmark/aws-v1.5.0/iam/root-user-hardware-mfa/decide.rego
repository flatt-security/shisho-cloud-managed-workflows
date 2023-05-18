package policy.aws.iam.root_user_hardware_mfa

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	enabled := find_hardware_mfa_field(
		account.iam.accountSummary.summaryMap,
		account.id,
		account.iam.virtualMfaDevices,
	)
	allowed := enabled

	d := shisho.decision.aws.iam.root_user_hardware_mfa({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.root_user_hardware_mfa_payload({"hardware_mfa_enabled": allowed}),
	})
}

find_hardware_mfa_field(summary, account_id, mfa_devices) {
	field := summary[_]
	field.key == "AccountMFAEnabled"
	field.value == 1

	has_virtual_mfa_device(account_id, mfa_devices) == false
} else = false

has_virtual_mfa_device(account_id, mfa_devices) {
	virtual_device_serial := sprintf("arn:aws:iam::%s:mfa/root-account-mfa-device", [account_id])

	device := mfa_devices[_]
	device.serialNumber == virtual_device_serial
} else = false
