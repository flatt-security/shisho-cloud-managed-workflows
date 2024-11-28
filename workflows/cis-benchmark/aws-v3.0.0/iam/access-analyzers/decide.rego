package policy.aws.iam.access_analyzers

import data.shisho
import future.keywords.every

# Add new regions to the list below if you want to ignore some regions in this policies
region_exceptions := (shisho.thirdparty.aws.opt_in_regions | shisho.thirdparty.aws.china_regions) | shisho.thirdparty.aws.gov_regions

decisions[d] {
	account := input.aws.accounts[_]
	analyzers := analyzer_names(account.iam.accessAnalyzers)

	d := shisho.decision.aws.iam.access_analyzers({
		"allowed": all_regions_covered(analyzers),
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.iam.access_analyzers_payload({
			"missing_regions": [r |
				r := shisho.thirdparty.aws.regions[_]
				not is_covered(r, {a.region | a := analyzers[_]})
			],
			"analyzers": analyzers,
		}),
	})
}

all_regions_covered(analyzers) {
	covered_regions := {a.region | a := analyzers[_]}
	every r in shisho.thirdparty.aws.regions {
		is_covered(r, covered_regions)
	}
} else := false

is_covered(r, covered_regions) {
	r in covered_regions
} else {
	r in region_exceptions
} else := false

analyzer_names(analyzers) := x {
	x := [{
		"analyzer_name": analyzer.name,
		"region": analyzer.region,
	} |
		analyzer := analyzers[_]
	]
}
