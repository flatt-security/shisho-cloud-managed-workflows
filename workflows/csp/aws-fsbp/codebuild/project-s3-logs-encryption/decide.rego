package policy.aws.codebuild.project_s3_logs_encryption

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	project := account.codeBuild.projects[_]

	project.logsConfiguration.s3Logs != null
	s3_logs := project.logsConfiguration.s3Logs

	d := shisho.decision.aws.codebuild.project_s3_logs_encryption({
		"allowed": allow_if_excluded(
			s3_logs.encryptionDisabled == false,
			project,
		),
		"subject": project.metadata.id,
		"payload": shisho.decision.aws.codebuild.project_s3_logs_encryption_payload({
			"bucket_name": s3_logs.location,
			"encryption_enabled": s3_logs.encryptionDisabled == false,
			"status": s3_logs.status,
		}),
	})
}

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
