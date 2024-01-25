package policy.googlecloud.logging.api_audit

import data.shisho

decisions[d] {
	project := input.googleCloud.projects[_]

	d := shisho.decision.googlecloud.logging.api_audit({
		"allowed": is_allowed(input.googleCloud.organizations, project),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.logging.api_audit_payload({"audit_configs": audit_logging_configs(project.iamPolicy.auditConfigurations)}),
	})
}

is_allowed(organizations, project) {
	has_organization_logging_configs(organizations, project)
} else {
	has_logging_configs(project.iamPolicy.auditConfigurations)
} else = false

has_organization_logging_configs(organizations, project) {
	# Find the organization that the project belongs to
	org := organizations[_]
	p := org.allProjects[_]
	p.metadata.id == project.metadata.id

	audit_config := org.iamPolicy.auditConfigurations[_]

	# check whether the service is `allServices`
	audit_config.service == "allServices"

	# check whether the configs include `ADMIN_READ`
	has_data_read(audit_config.configurations)

	# check whether `DATA_READ` config has empty exempted members
	has_admin_read(audit_config.configurations)

	# check whether the configs include `DATA_WRITE`
	has_data_write(audit_config.configurations)
} else = false

has_logging_configs(audit_configurations) {
	audit_config := audit_configurations[_]

	# check whether the service is `allServices`
	audit_config.service == "allServices"

	# check whether the configs include `ADMIN_READ`
	has_data_read(audit_config.configurations)

	# check whether `DATA_READ` config has empty exempted members
	has_admin_read(audit_config.configurations)

	# check whether the configs include `DATA_WRITE`
	has_data_write(audit_config.configurations)
} else = false

has_data_read(configurations) {
	config := configurations[_]
	config.type == "DATA_READ"
	count(config.exemptedMembers) == 0
} else = false

has_data_write(configurations) {
	config := configurations[_]
	config.type == "DATA_WRITE"
	count(config.exemptedMembers) == 0
} else = false

# `ADMAIN_READ` is mandaroty but check whether exempted members are empty
has_admin_read(configurations) {
	config := configurations[_]

	config.type == "ADMIN_READ"
	count(config.exemptedMembers) == 0
} else = false

audit_logging_configs(audit_configurations) := x {
	x := [{
		"service": audit_config.service,
		"audit_log_configs": logging_configs(audit_config.configurations),
	} |
		audit_config := audit_configurations[_]
	]
}

logging_configs(configurations) := x {
	x := [{
		"audit_log_config_log_type": log_type(config.type),
		"exempted_members": config.exemptedMembers,
	} |
		config := configurations[_]
	]
}

log_type(t) = shisho.decision.googlecloud.logging.AUDIT_LOG_CONFIG_LOG_TYPE_ADMIN_READ {
	t == "ADMIN_READ"
} else = shisho.decision.googlecloud.logging.AUDIT_LOG_CONFIG_LOG_TYPE_DATA_READ {
	t == "DATA_WRITE"
} else = shisho.decision.googlecloud.logging.AUDIT_LOG_CONFIG_LOG_TYPE_DATA_WRITE {
	t == "DATA_READ"
} else = shisho.decision.googlecloud.logging.AUDIT_LOG_CONFIG_LOG_TYPE_LOG_TYPE_UNSPECIFIED
