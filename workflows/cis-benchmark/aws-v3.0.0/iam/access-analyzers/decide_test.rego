package policy.aws.iam.access_analyzers

import data.shisho
import future.keywords

test_whether_the_access_analyzers_is_enabled_for_each_region if {
	# check if the Access Analyzer is enabled for each region
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"metadata": {
			"id": "aws-account|779392188888",
			"displayName": "779392188888",
		},
		"iam": {"accessAnalyzers": [
			{
				"region": "ap-northeast-1",
				"name": "ConsoleAnalyzer-181dba79-617f-4755-a816-b9055b188888",
			},
			{
				"region": "ap-northeast-2",
				"name": "ConsoleAnalyzer-181dba79-617f-4755-a816-b9055b188888",
			},
		]},
	}]}}
		with data.shisho.thirdparty.aws.regions as {"ap-northeast-1", "ap-northeast-2"}

	# check if the Access Analyzer is enabled for each region
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {
				"id": "aws-account|779392177777",
				"displayName": "779392177777",
			},
			"iam": {"accessAnalyzers": []},
		},
		{
			"metadata": {
				"id": "aws-account|779392188888",
				"displayName": "779392188888",
			},
			"iam": {"accessAnalyzers": [{
				"region": "ap-northeast-1",
				"name": "ConsoleAnalyzer-181dba79-617f-4755-a816-b9055b188888",
			}]},
		},
	]}}
		with data.shisho.thirdparty.aws.regions as {"ap-northeast-1", "ap-northeast-2"}
}
