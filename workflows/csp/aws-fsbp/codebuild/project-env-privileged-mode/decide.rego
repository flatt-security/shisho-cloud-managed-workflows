package policy.aws.codebuild.project_env_privileged_mode

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	project := account.codeBuild.projects[_]

	d := shisho.decision.aws.codebuild.project_env_privileged_mode({
		"allowed": allow_if_excluded(
			project.environment.privilegedMode == false,
			project,
		),
		"subject": project.metadata.id,
		"payload": shisho.decision.aws.codebuild.project_env_privileged_mode_payload({"privileged_mode_enabled": project.environment.privilegedMode}),
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
