package policy.aws.codebuild.project_source_repository_credential

import data.shisho
import future.keywords.in

decisions[d] {
	account := input.aws.accounts[_]
	project := account.codeBuild.projects[_]

	# targert sources are either GITHUB and BITBUCKET
	project.source.type in ["GITHUB", "GITHUB_ENTERPRISE", "BITBUCKET"]

	auth := auth_config(project.source)

	d := shisho.decision.aws.codebuild.project_source_repository_credential({
		"allowed": allow_if_excluded(
			auth.type == "OAUTH",
			project,
		),
		"subject": project.metadata.id,
		"payload": shisho.decision.aws.codebuild.project_source_repository_credential_payload({
			"source_type": project.source.type,
			"auth": auth,
		}),
	})
}

auth_config(project_source) = {"type": project_source.auth.type, "arn": project_source.auth.arn} {
	project_source != null
} else = {"type": "", "arn": ""}

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
