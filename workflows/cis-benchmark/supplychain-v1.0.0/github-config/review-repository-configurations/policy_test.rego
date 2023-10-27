package policy.github.config.review_branch_protection_rule

import data.shisho
import future.keywords

test_whether_branch_protections_are_configured_for_default_branch if {
	# it is better to configure the branch protections which allow to control user's activities
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{"pattern": "test-repo"}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}

	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{"pattern": "test-repo"}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
		with data.params as {"archived_repositories_riskiness": "riskful"}

	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{"pattern": "test-repo"}],
		"isArchived": true,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}

	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{"pattern": "test-repo"}],
		"isArchived": true,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
		with data.params as {"archived_repositories_riskiness": "riskful"}

	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"isArchived": false,
		"branchProtections": [],
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
		with data.params as {"archived_repositories_riskiness": "riskful"}

	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [],
		"isArchived": true,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_default_branch_protection"
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"isArchived": true,
		"branchProtections": [],
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
		with data.params as {"archived_repositories_riskiness": "riskful"}
}

test_whether_code_owner_reviews_are_required_for_default_branch if {
	# it is better to require the review of code owners to prevent unexpected updates
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_code_owners_review_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"pattern": "test-repo",
			"requiresCodeOwnerReviews": true, # require the review of code owners
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_approving_review_count_is_more_than_one_for_default_branch if {
	# it is better to require at least a few numbers of approvals before the merge to prevent unexpected modifications
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_minimum_approval_number_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"pattern": "test-repo",
			"requiredApprovingReviewCount": 1, # require at least one approval
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_admin_is_enforced_for_default_branch if {
	# it is better to enforce admins to prevent unexpected updates
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_protection_enforcement_for_admins"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"isAdminEnforced": true, # = enforce admins
			"pattern": "test-repo",
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_stale_reviews_are_dismissed_for_default_branch if {
	# it is better to dismiss stale pull request approvals when new commits are pushed to prevent unexpected merge
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_stale_review_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"dismissesStaleReviews": true, # = dismiss stale reviews (= stale pull request approvals before the new commmits are pushed)
			"pattern": "test-repo",
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_commit_signatures_are_required_for_default_branch if {
	# it is better to require commit signatures to prevent unexpected updates
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_commit_signature_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"requiresCommitSignatures": true, # = require commit signatures
			"pattern": "test-repo",
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_force_pushes_are_not_allowed_for_default_branch if {
	# it is better to deny force pushes to prevent unexpected updates
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_force_push_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"allowsForcePushes": false, # = does not allow force pushes
			"pattern": "test-repo",
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_linear_history_is_required_for_default_branch if {
	# it is better to require linear histoies for tracking them
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_linear_history_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"requiresLinearHistory": true, # = require linear histoies
			"pattern": "test-repo",
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}

test_whether_deletions_are_not_allowed_for_default_branch if {
	# it is better to deny deletions to prevent the unexpected deletion
	count([d |
		decisions[d]
		d.header.api_version = "decision.api.shisho.dev/v1beta"
		d.header.kind = "github_branch_deletion_policy"
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"github": {"organizations": [{"repositories": [{
		"branchProtections": [{
			"allowsDeletions": false, # = does not allow deletions
			"pattern": "test-repo",
		}],
		"isArchived": false,
		"defaultBranchRef": {"name": "test-repo"},
		"metadata": {"id": "github-repository|738748884-338212877"},
	}]}]}}
}
