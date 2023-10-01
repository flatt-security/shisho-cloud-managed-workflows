package policy.aws.securityhub.usage

import data.shisho
import future.keywords.every

# Add new regions to the list below if you want to ignore some regions in this policies
region_exceptions := (shisho.thirdparty.aws.opt_in_regions | shisho.thirdparty.aws.china_regions) | shisho.thirdparty.aws.gov_regions

decisions[d] {
	account := input.aws.accounts[_]

	enabled_regions := [s.region |
		s := account.securityHub.subscriptions[_]
		s.subscribed
	]
	d := shisho.decision.aws.securityhub.usage({
		"allowed": enabled_in_all_regions(account.securityHub.subscriptions),
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.securityhub.usage_payload({
			"enabled_regions": enabled_regions,
			"missing_regions": [r |
				r := shisho.thirdparty.aws.regions[_]
				not is_covered(r, enabled_regions)
			],
		}),
	})
}

enabled_in_all_regions(subscriptions) {
	covered_regions := {s.region |
		s := subscriptions[_]
		s.subscribed
	}
	every r in shisho.thirdparty.aws.regions {
		is_covered(r, covered_regions)
	}
} else := false

is_covered(r, covered_regions) {
	r in covered_regions
} else {
	r in region_exceptions
} else := false
