package policy.aws.iam.account_alternate_contact

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	contact_state := account.alternateContactState

	d := shisho.decision.aws.iam.account_alternate_contact({
		"allowed": contact_state.securityContactRegistered,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.account_alternate_contact_payload({
			"contact_for_security_registered": contact_state.securityContactRegistered,
			"contact_for_billing_registered": contact_state.billingContactRegistered,
			"contact_for_operations_registered": contact_state.operationsContactRegistered,
		}),
	})
}
