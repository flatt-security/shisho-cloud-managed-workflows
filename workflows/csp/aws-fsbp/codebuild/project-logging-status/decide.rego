package policy.aws.codebuild.project_logging_status

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	project := account.codeBuild.projects[_]

	cloudwatch_logs := cloudwatch_log_status(project.logsConfiguration)
	s3_logs := s3_log_status(project.logsConfiguration)

	d := shisho.decision.aws.codebuild.project_logging_status({
		"allowed": allow_if_excluded(
			is_log_enabled(cloudwatch_logs, s3_logs),
			project,
		),
		"subject": project.metadata.id,
		"payload": shisho.decision.aws.codebuild.project_logging_status_payload({
			"cloudwatch_logs": cloudwatch_logs,
			"s_3_logs": s3_logs,
		}),
	})
}

is_log_enabled(cloudwatch_logs, s3_logs) = false {
	cloudwatch_logs.status == "DISABLED"
	s3_logs.status == "DISABLED"
} else = true

cloudwatch_log_status(logs_configuration) = {
	"group_name": cloudwatch_logs.groupName,
	"stream_name": cloudwatch_logs.streamName,
	"status": cloudwatch_logs.status,
} {
	logs_configuration.cloudWatchLogs != null
	cloudwatch_logs := logs_configuration.cloudWatchLogs
} else = {"group_name": "", "stream_name": "", "status": "DISABLED"}

s3_log_status(logs_configuration) = {"bucket_name": s3_logs.location, "status": s3_logs.status} {
	logs_configuration.s3Logs != null
	s3_logs := logs_configuration.s3Logs
} else = {"bucket_name": "", "status": "DISABLED"}

allow_if_excluded(allowed, r) {
	data.params != null

	tag := data.params.tag_exceptions[_]
	elements := split(tag, "=")

	tag_key := elements[0]
	tag_value := concat("=", array.slice(elements, 1, count(elements)))

	t := r.tags[_]
	t.key == tag_key
	t.value == tag_value
} else := allowed
