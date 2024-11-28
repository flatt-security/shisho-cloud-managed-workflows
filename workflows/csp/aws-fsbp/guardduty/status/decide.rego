package policy.aws.guardduty.status

import data.shisho
import future.keywords.in

# this is a list of excluded regions
# if you want to exclude some regions, please adjust them
excluded_regions = ["dummy-region"]

decisions[d] {
	account := input.aws.accounts[_]
	configs := account.guardDuty.configurations

	h := has_uncovered_regions(configs)

	d := shisho.decision.aws.guardduty.status({
		"allowed": h == false,
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.guardduty.status_payload({"guardduty_status": configs}),
	})
}

enabled_regions(configurations) := {config.region |
	config := configurations[_]
	config.enabled == true
}

has_uncovered_regions(configurations) {
	count(uncovered_regions(configurations)) > 0
} else = false

uncovered_regions(configurations) := [r |
	r := shisho.thirdparty.aws.regions[_]
	not r in excluded_regions
	not r in enabled_regions(configurations)
]
