package policy.aws.securityhub.usage

import data.shisho
import future.keywords

test_policy_security_hub_is_subscribed if {
	# check if Security Hub is subscribed in all regions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"metadata": {"id": "aws-account|779392187777"},
		"securityHub": {"subscriptions": [
			{
				"region": "ap-northeast-2",
				"subscribed": true,
			},
			{
				"region": "ap-northeast-1",
				"subscribed": true,
			},
		]},
	}]}}
		with data.shisho.thirdparty.aws.regions as {"ap-northeast-1", "ap-northeast-2"}

	# check if Security Hub is not subscribed
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"metadata": {"id": "aws-account|779392187777"},
		"securityHub": {"subscriptions": [
			{
				"region": "ap-northeast-2",
				"subscribed": true,
			},
			{
				"region": "ap-northeast-1",
				"subscribed": false,
			},
		]},
	}]}}
		with data.shisho.thirdparty.aws.regions as {"ap-northeast-1", "ap-northeast-2"}
}
