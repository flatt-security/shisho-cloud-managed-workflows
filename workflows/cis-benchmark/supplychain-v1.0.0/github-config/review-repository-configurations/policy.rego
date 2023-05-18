package policy.github.config.review_branch_protection_rule

import data.shisho

import future.keywords.every
import future.keywords.in

archived_repositories_riskful {
	data.params != null
	data.params.archived_repositories_riskiness == "riskful"
} else = false

allow_if_excluded_or(is_archived, allowed) {
	# if the archived repo is not included, and the repo is archived, then it must be allowed forcibly
	not archived_repositories_riskful
	is_archived
} else = allowed

pattern_match(pattern, name) {
	pattern == name
} else = false

bpr_match(rules, name) {
	some r in rules
	pattern_match(r.pattern, name)
} else = false

# Review the status of branch protection rules for default branches
###################################

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	allowed := allow_if_excluded_or(repo.isArchived, bpr_match(repo.branchProtections, repo.defaultBranchRef.name))
	d := shisho.decision.github.default_branch_protection({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.default_branch_protection_payload({"default_branch_name": repo.defaultBranchRef.name}),
	})
}

# Review code review policies
###################################

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.requiresCodeOwnerReviews
	]

	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) > 0)
	d := shisho.decision.github.code_owners_review_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.code_owners_review_policy_payload({
			"required": count(filtered) > 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	rule := repo.branchProtections[_]
	pattern_match(rule.pattern, repo.defaultBranchRef.name)

	allowed := allow_if_excluded_or(repo.isArchived, rule.requiredApprovingReviewCount >= 1)

	d := shisho.decision.github.minimum_approval_number_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.minimum_approval_number_policy_payload({
			"required_approval_count": rule.requiredApprovingReviewCount,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.isAdminEnforced
	]

	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) > 0)
	d := shisho.decision.github.protection_enforcement_for_admins({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.protection_enforcement_for_admins_payload({
			"allowed": count(filtered) > 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.dismissesStaleReviews
	]

	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) > 0)
	d := shisho.decision.github.stale_review_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.stale_review_policy_payload({
			"enforced": count(filtered) > 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

# Review commit signature policies
###################################

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.requiresCommitSignatures
	]
	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) > 0)
	d := shisho.decision.github.commit_signature_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.commit_signature_policy_payload({
			"required": count(filtered) > 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

# Review commit history security
###################################

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.allowsForcePushes
	]
	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) == 0)
	d := shisho.decision.github.force_push_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.force_push_policy_payload({
			"allowed": count(filtered) == 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.requiresLinearHistory
	]

	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) > 0)
	d := shisho.decision.github.linear_history_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.linear_history_policy_payload({
			"required": count(filtered) > 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	filtered := [rule |
		rule := repo.branchProtections[_]
		pattern_match(rule.pattern, repo.defaultBranchRef.name)
		rule.allowsDeletions
	]

	allowed := allow_if_excluded_or(repo.isArchived, count(filtered) == 0)
	d := shisho.decision.github.branch_deletion_policy({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.branch_deletion_policy_payload({
			"allowed": count(filtered) == 0,
			"subject_branch": repo.defaultBranchRef.name,
		}),
	})
}

# Review repository-level permissions
###################################

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	admins := [c.login |
		c := repo.collaborators[_]
		c.permission == "ADMIN"
	]

	allowed := allow_if_excluded_or(repo.isArchived, count(admins) <= 2)
	d := shisho.decision.github.repo_admins({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.repo_admins_payload({"admins": admins}),
	})
}

decisions[d] {
	org := input.github.organizations[_]
	repo := org.repositories[_]

	admins := [c.login |
		c := repo.collaborators[_]
		c.permission == "ADMIN"
	]
	allowed := allow_if_excluded_or(repo.isArchived, count(admins) <= 2)

	d := shisho.decision.github.repo_members_permission_on_deleting_repository({
		"allowed": allowed,
		"subject": repo.metadata.id,
		"payload": shisho.decision.github.repo_members_permission_on_deleting_repository_payload({"allowed_users": admins}),
	})
}
