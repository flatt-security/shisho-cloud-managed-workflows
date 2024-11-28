package policy.aws.codebuild.project_env_variables

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	project := account.codeBuild.projects[_]

	variables := environment_variables(project.environment)

	d := shisho.decision.aws.codebuild.project_env_variables({
		"allowed": allow_if_excluded(is_no_env_variables(variables), project),
		"subject": project.metadata.id,
		"payload": shisho.decision.aws.codebuild.project_env_variables_payload({"environment_variables": variables}),
	})
}

is_no_env_variables(variables) = false {
	variable := variables[_]
	variable.type == "PLAINTEXT"
	[
		contains(variable.name, "AWS_ACCESS_KEY_ID"),
		contains(variable.name, "AWS_SECRET_ACCESS_KEY"),
		contains(variable.name, "PASSWORD"),
	][_] == true
} else = true

environment_variables(environment) = x {
	x := [{"type": variable.type, "name": variable.name} |
		variable := environment.environmentVariables[_]
	]
} else = []

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
