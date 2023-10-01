package policy.googlecloud.iam.principal_source

import data.shisho
import future.keywords.every

# please adjust these lists to your needs
# the list of allowed source domains
allowed_source_domains := data.params.allowed_principal_domains {
	data.params != null
	data.params.allowed_principal_domains != null
} else := ["testcompany.com", "testcompany2.com"]

# the list of allowed source domains using regex
allowed_regex_source_domains := data.params.allowed_principal_domain_regexes {
	data.params != null
	data.params.allowed_principal_domain_regexes != null
} else := ["testcompany.*\\.com$"]

decisions[d] {
	project := input.googleCloud.projects[_]
	ds := domains(project.iamPolicy.bindings)

	d := shisho.decision.googlecloud.iam.principal_source({
		"allowed": has_only_allowed_domains(ds),
		"subject": project.metadata.id,
		"payload": shisho.decision.googlecloud.iam.principal_source_payload({"source_domains": ds}),
	})
}

domains(bindings) := x {
	x := {domain |
		binding := bindings[_]
		member := binding.members[_]
		[
			"GoogleCloudIAMPrincipalUser",
			"GoogleCloudIAMPrincipalGroup",
		][_] == member.__typename

		not member.deleted
		elements := split(member.email, "@")
		domain := elements[1]
	} | {member.domain |
		binding := bindings[_]
		member := binding.members[_]
		member.__typename == "GoogleCloudIAMPrincipalDomain"
	}
} else = {}

has_only_allowed_domains(ds) {
	every d in ds {
		is_allowed_domain(d)
	}
} else := false

is_allowed_domain(d) {
	allowed_source_domains[_] == d
} else {
	regex.match(allowed_regex_source_domains[_], d)
} else := false
