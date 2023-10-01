package policy.googlecloud.logging.full_export

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	empty_filter_sinks := sinks_for_all_entries(project.cloudLogging.sinks)

	d := shisho.decision.googlecloud.logging.full_export({
		"allowed": count(empty_filter_sinks) > 0,
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.logging.full_export_payload({"empty_filter_sinks": empty_filter_sinks}),
	})
}

sinks_for_all_entries(sinks) := x {
	x := [sink.name |
		sink := sinks[_]

		# the sink must include all
		sink.filter == ""

		# the sink must not exclude any
		count(sink.exclusions) == 0

		# the sink must have a destination
		sink.destination != ""
	]
} else = []
