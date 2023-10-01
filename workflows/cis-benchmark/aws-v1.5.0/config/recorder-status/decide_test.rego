package policy.aws.config.recorder_status

import data.shisho
import future.keywords

test_policy_config_is_enabled_and_recording if {
	# check if Config is enabled and recording
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 1 with input as {"aws": {"accounts": [{
		"metadata": {"id": "aws-account|779392187777"},
		"config": {"recorders": [
			{
				"name": "aa",
				"metadata": {
					"id": "aws-config-recorder|ap-northeast-1|test-recorder-1",
					"displayName": "test-recorder-1",
				},
				"region": "ap-northeast-1",
				"recordingGroup": {
					"allSupported": true,
					"includeGlobalResourceTypes": true,
					"resourceTypes": [],
				},
				"status": {
					"lastStatus": "SUCCESS",
					"recording": true,
				},
			},
			{
				"name": "aa",
				"metadata": {
					"id": "aws-config-recorder|ap-northeast-1|test-recorder-2",
					"displayName": "test-recorder-2",
				},
				"region": "ap-northeast-2",
				"recordingGroup": {
					"allSupported": true,
					"includeGlobalResourceTypes": true,
					"resourceTypes": [],
				},
				"status": {
					"lastStatus": "SUCCESS",
					"recording": true,
				},
			},
		]},
	}]}}
		with data.shisho.thirdparty.aws.regions as {"ap-northeast-1", "ap-northeast-2"}

	# check if Config is enabled and recording
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [
		{
			"metadata": {"id": "aws-account|779392187777"},
			"config": {"recorders": [{
				"name": "aa",
				"metadata": {
					"id": "aws-config-recorder|ap-northeast-1|test-recorder-1",
					"displayName": "test-recorder-1",
				},
				"region": "ap-northeast-1",
				"recordingGroup": {
					"allSupported": true,
					"includeGlobalResourceTypes": true,
					"resourceTypes": [],
				},
				"status": {
					"lastStatus": "SUCCESS",
					"recording": true,
				},
			}]},
		},
		{
			"metadata": {"id": "aws-account|779392187888"},
			"config": {"recorders": [{
				"name": "aa",
				"metadata": {
					"id": "aws-config-recorder|ap-northeast-1|test-recorder-1",
					"displayName": "test-recorder-1",
				},
				"region": "ap-northeast-2",
				"recordingGroup": {
					"allSupported": true,
					"includeGlobalResourceTypes": true,
					"resourceTypes": [],
				},
				"status": {
					"lastStatus": "SUCCESS",
					"recording": true,
				},
			}]},
		},
	]}}
		with data.shisho.thirdparty.aws.regions as {"ap-northeast-1", "ap-northeast-2"}
}
