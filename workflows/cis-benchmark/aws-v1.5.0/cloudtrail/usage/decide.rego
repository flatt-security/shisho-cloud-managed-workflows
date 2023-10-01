package policy.aws.cloudtrail.usage

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]

	d := shisho.decision.aws.cloudtrail.usage({
		"allowed": has_compliant_trail(account.cloudTrail.trails),
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.cloudtrail.usage_payload({"trail_arns": [t.arn | t := account.cloudTrail.trails[_]]}),
	})
}

has_compliant_trail(trails) {
	trail := trails[_]

	# The trail is enabled in all regions ...
	trail.isMultiRegionTrail == true

	# ... and actively logging ...
	trail.status.isLogging == true

	# ... and is configured to log all events ...
	count(trail.eventSelectors) > 0
	eventSelector := trail.eventSelectors[_]
	eventSelector.includeManagementEvents == true
	eventSelector.readWriteType == "ALL"
} else = false
