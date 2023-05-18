package policy.googlecloud.compute.disk_encryption_key

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	instance := project.computeEngine.instances[_]

	keys := non_csek_keys(instance.disks)
	d := shisho.decision.googlecloud.compute.disk_encryption_key({
		"allowed": count(keys) == 0,
		"subject": instance.metadata.id,
		"payload": shisho.decision.googlecloud.compute.disk_encryption_key_payload({"keys": keys}),
	})
}

non_csek_keys(disks) := x {
	x := [{
		"target_disk": disk.deviceName,
		"key_name": disk.diskEncryptionKey.kmsKeyName,
		"key_type": key_type,
	} |
		disk := disks[_]
		key_type := encryption_key_type(disk.diskEncryptionKey)
		key_type != shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_ENCRYPTION_KEY_TYPE_CUSTOMER_SUPPLIED
	]
} else := [] {
	true
}

# key.kmsKeyName: The name of the encryption key that is stored in Google Cloud KMS
# key.kmsKeyServiceAccount: /The service account being used for the encryption request for the given KMS key
# key.sha256: The RFC 4648 base64 encoded SHA-256 hash of the customer-supplied encryption key that protects this resource
encryption_key_type(key) = shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_NONE {
	key == null
} else = shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_NONE {
	# If this is empty, the encryption key is disabled
	key.kmsKeyName == ""
} else = shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_ENCRYPTION_KEY_TYPE_GOOGLE_MANAGED {
	# If this is not empty, the encryption key is enabled
	key.kmsKeyName != ""

	# If this is empty, the Compute Engine default service account is used
	key.kmsKeyServiceAccount == ""
} else = shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_ENCRYPTION_KEY_TYPE_CUSTOMER_MANAGED {
	# If this is not empty, the encryption key is enabled
	key.kmsKeyName != ""

	# If this is not empty, the customer supplied service account is used
	key.kmsKeyServiceAccount != ""

	# If this is empty, this is not the customer-supplied encryption key
	key.sha256 == ""
} else = shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_ENCRYPTION_KEY_TYPE_CUSTOMER_SUPPLIED {
	# If this is not empty, the encryption key is enabled
	key.kmsKeyName != ""

	# If this is not empty, the customer supplied service account is used
	key.kmsKeyServiceAccount != ""

	# If this is not empty, this is the customer-supplied encryption key
	key.sha256 != ""
} else = shisho.decision.googlecloud.compute.ENCRYPTION_KEY_TYPE_ENCRYPTION_KEY_TYPE_UNKNOWN {
	true
}
