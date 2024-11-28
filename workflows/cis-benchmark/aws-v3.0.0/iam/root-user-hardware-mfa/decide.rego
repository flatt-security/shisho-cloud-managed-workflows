package policy.aws.iam.root_user_hardware_mfa

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	contents := account.iam.credentialReport.contents

	enabled := root_user_uses_hardware_mfa(
		account.id,
		account.iam.virtualMfaDevices,
		contents,
	)

	allowed := enabled

	d := shisho.decision.aws.iam.root_user_hardware_mfa({
		"allowed": allowed,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.root_user_hardware_mfa_payload({"hardware_mfa_enabled": allowed}),
	})
}

root_user_mfa_active(contents) {
	content := contents[_]
	content.user == "<root_account>"
	content.mfaActive == true
}

root_user_has_virtual_mfa_device(account_id, mfa_devices) {
	device := mfa_devices[_]
	endswith(device.user.arn, ":root")
} else = false

root_user_uses_hardware_mfa(account_id, mfa_devices, contents) {
	root_user_mfa_active(contents)
	root_user_has_virtual_mfa_device(account_id, mfa_devices) == false
} else = false
