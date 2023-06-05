package policy.aws.elb.deletion_protection

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	lb := account.elb.loadBalancers[_]

	enabled := lb.attributes.enabledDeletionProtection
	allowed := enabled

	d := shisho.decision.aws.alb.delete_protection({
		"allowed": allowed,
		"subject": lb.metadata.id,
		"payload": shisho.decision.aws.alb.delete_protection_payload({"deletion_protection_enabled": enabled}),
	})
}
