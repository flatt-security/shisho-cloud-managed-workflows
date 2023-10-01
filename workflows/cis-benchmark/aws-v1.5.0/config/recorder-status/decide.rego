package policy.aws.config.recorder_status

import data.shisho
import future.keywords.every

# Add new regions to the list below if you want to ignore some regions in this policies
region_exceptions := (shisho.thirdparty.aws.opt_in_regions | shisho.thirdparty.aws.china_regions) | shisho.thirdparty.aws.gov_regions

decisions[d] {
	account := input.aws.accounts[_]
	d := shisho.decision.aws.config.recorder_status({
		"allowed": all_regions_covered(account.config.recorders),
		"subject": account.metadata.id,
		"payload": shisho.decision.aws.config.recorder_status_payload({
			"missing_regions": [r |
				r := shisho.thirdparty.aws.regions[_]
				not is_covered(r, [r.region |
					r := account.config.recorders[_]
					is_valid_recorder(r)
				])
			],
			"recorders": [{
				"name": recorder.name,
				"region": recorder.region,
				"recording_group": {
					"all_supported": recorder.recordingGroup.allSupported,
					"include_global_resource_types": recorder.recordingGroup.includeGlobalResourceTypes,
					"resource_types": recorder.recordingGroup.resourceTypes,
				},
			} |
				recorder := account.config.recorders[_]
			],
		}),
	})
}

all_regions_covered(recorders) {
	covered_regions := {r.region |
		r := recorders[_]
		is_valid_recorder(r)
	}

	every r in shisho.thirdparty.aws.regions {
		is_covered(r, covered_regions)
	}
} else := false

is_valid_recorder(r) {
	r.recordingGroup.allSupported == true
	r.recordingGroup.includeGlobalResourceTypes == true

	r.status.lastStatus == "SUCCESS"
	r.status.recording == true
} else := false

is_covered(r, covered_regions) {
	r in covered_regions
} else {
	r in region_exceptions
} else := false
