package policy.aws.flatt.iam.assumerole

import data.shisho

decisions[d] {
	account := input.aws.accounts[_]
	role := account.iam.roles[_]

	r := json.unmarshal(role.assumeRoleRawPolicyDocument)
	reviewed := [x |
		s := r.Statement[_]
		s.Effect == "Allow"

		x := review(account, s)
		x != null
	]

	d := shisho.decision.new({
		"api_version": "decision.api.shisho.dev/v1",
		"kind": "aws_iam_assumerole_policy",
		"subject": role.metadata.id,
		"locator": "",
		"severity": determine_severity(reviewed, role),
		"allowed": count(reviewed) == 0,
		"payload": json.marshal({"possible_caller_identities": [{
			"principal": x.principal,
			"statement": x.statement,
			"permissiveReason": x.permissiveReason,
			"suggestedCondition": x.suggestedCondition,
		} |
			x := reviewed[_]
		]}),
	})
}

determine_severity(reviewed, r) = max([x.severity |
	x := reviewed[_]
]) {
	count(reviewed) > 0
	count(r.policies) > 0
} else = shisho.decision.severity_info

review(a, s) = {
	"principal": s.Principal,
	"permissiveReason": "All principals are allowed",
	"suggestedCondition": "",
	"severity": shisho.decision.severity_critical,
	"statement": s,
} {
	s.Principal.AWS == "*"
	not has_effective_condition(s)
} else := {
	"principal": s.Principal,
	"permissiveReason": "All principals are allowed",
	"suggestedCondition": "",
	"severity": shisho.decision.severity_critical,
	"statement": s,
} {
	s.Principal == "*"
	not has_effective_condition(s)
} else := {
	"principal": s.Principal,
	"permissiveReason": "Any resources in the account are allowed",
	"suggestedCondition": "",
	"severity": shisho.decision.severity_high,
	"statement": s,
} {
	regex.match("arn:aws:iam::[0-9]+:root", s.Principal.AWS)
	not has_effective_condition(s)
} else := {
	"principal": s.Principal,
	"permissiveReason": "Any resources in the service are allowed",
	"suggestedCondition": "",
	"severity": shisho.decision.severity_medium,
	"statement": s,
} {
	s.Principal.Service != null
	not has_effective_condition(s)
} else := {
	"principal": s.Principal,
	"permissiveReason": "Any GitHub repo can assume the role",
	"suggestedCondition": "",
	"severity": shisho.decision.severity_critical,
	"statement": s,
} {
	regex.match("arn:aws:iam::[0-9]+:oidc-provider/token.actions.githubusercontent.com", s.Principal.Federated)
	not has_strict_gh_condition(s)
} else := {
	"principal": s.Principal,
	"permissiveReason": "Any GitLab repo can assume the role",
	"suggestedCondition": "",
	"severity": shisho.decision.severity_critical,
	"statement": s,
} {
	regex.match("arn:aws:iam::[0-9]+:oidc-provider/gitlab.com", s.Principal.Federated)
	not has_strict_gitlab_condition(s)
} else := null

has_strict_gh_condition(s) {
	s.Condition != null
	s.Condition.StringLike != null
	regex.match("repo:[^:*]+/[^:*]+:.*", s.Condition.StringLike["token.actions.githubusercontent.com:sub"])
} else {
	s.Condition != null
	s.Condition.StringEquals != null
	regex.match("repo:[^:*]+/[^:*]+:.*", s.Condition.StringEquals["token.actions.githubusercontent.com:sub"])
} else = false

has_strict_gitlab_condition(s) {
	s.Condition != null
	s.Condition.StringLike != null
	regex.match("project_path:[^:]+/[^:]+:.*", s.Condition.StringLike["gitlab.example.com:sub"])
} else {
	s.Condition != null
	s.Condition.StringEquals != null
	regex.match("project_path:[^:]+/[^:]+:.*", s.Condition.StringEquals["gitlab.example.com:sub"])
} else = false

has_effective_condition(s) {
	s.Condition != null
	has_any_of_context_keys(
		[
			"aws:SourceArn",
			"aws:SourceAccount",
		],
		s.Condition,
	)
} else = false

has_any_of_context_keys(keys, s) {
	k := keys[_]
	s.Condition.StringEquals[k] != null
} else {
	k := keys[_]
	s.Condition.StringLike[k] != null
} else {
	k := keys[_]
	s.Condition.StringNotEquals[k] != null
} else {
	k := keys[_]
	s.Condition.StringNotLike[k] != null
} else {
	k := keys[_]
	s.Condition.StringEqualsIgnoreCase[k] != null
} else {
	k := keys[_]
	s.Condition.StringLikeIgnoreCase[k] != null
} else {
	k := keys[_]
	s.Condition.ArnLike[k] != null
} else {
	k := keys[_]
	s.Condition.ArnEquals[k] != null
} else {
	k := keys[_]
	s.Condition.ArnNotLike[k] != null
} else {
	k := keys[_]
	s.Condition.ArnNotEquals[k] != null
} else = false
