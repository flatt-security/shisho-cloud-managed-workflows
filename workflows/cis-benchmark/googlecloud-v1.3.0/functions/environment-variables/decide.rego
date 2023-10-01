package policy.googlecloud.functions.environment_variables

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]
	function := project.cloudFunctions.functions[_]

	build_env_variables := [variable.key |
		variable := function.buildConfiguration.environmentVariables[_]
	]

	service_env_variables := [variable.key |
		variable := function.serviceConfiguration.environmentVariables[_]
	]

	d := shisho.decision.googlecloud.functions.environment_variables({
		"allowed": has_no_env_variables(build_env_variables, service_env_variables),
		"subject": function.metadata.id,
		"payload": shisho.decision.googlecloud.functions.environment_variables_payload({
			"build_environment_variable_keys": build_env_variables,
			"service_environment_variable_keys": service_env_variables,
		}),
	})
}

# This policy reviews key names only, not values. One can improve this detection by using more sophisticated list of keywords, or introducing value-based detection.
suspicious_pieces := ["TOKEN", "SECRET", "KEY", "PASSWORD"]

has_no_env_variables(build_env_variables, service_env_variables) {
	not contains_suspicious_key(build_env_variables)
	not contains_suspicious_key(service_env_variables)
} else = false

contains_suspicious_key(keys) {
	contains(upper(keys[_]), suspicious_pieces[_])
} else := false
