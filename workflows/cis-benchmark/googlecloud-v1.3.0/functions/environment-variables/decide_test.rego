package policy.googlecloud.functions.environment_variables

import data.shisho
import future.keywords

test_whether_environment_variables_are_not_used_for_cloud_functions if {
	# check if environment variables are not used for Cloud Functions
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudFunctions": {"functions": [
		{
			"metadata": {
				"id": "googlecloud-cf-function|514897777777|projects/test-project-1/locations/asia-northeast1/functions/function-1",
				"displayName": "projects/test-project-1/locations/asia-northeast1/functions/function-1",
			},
			"buildConfiguration": {"environmentVariables": []},
			"serviceConfiguration": {"environmentVariables": []},
		},
		{
			"metadata": {
				"id": "googlecloud-cf-function|514897777777|projects/test-project-1/locations/asia-northeast1/functions/function-2",
				"displayName": "projects/test-project-1/locations/asia-northeast1/functions/function-2",
			},
			"buildConfiguration": {"environmentVariables": []},
			"serviceConfiguration": {"environmentVariables": []},
		},
	]}}]}}

	# check if environment variables are not used for Cloud Functions
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudFunctions": {"functions": [
		{
			"metadata": {
				"id": "googlecloud-cf-function|514897777777|projects/test-project-1/locations/asia-northeast1/functions/function-1",
				"displayName": "projects/test-project-1/locations/asia-northeast1/functions/function-1",
			},
			"buildConfiguration": {"environmentVariables": [{"key": "TEST_VALUE"}]},
			"serviceConfiguration": {"environmentVariables": [{"key": "TEST_RUNTIME_KEY"}]},
		},
		{
			"metadata": {
				"id": "googlecloud-cf-function|514897777777|projects/test-project-1/locations/asia-northeast1/functions/function-2",
				"displayName": "projects/test-project-1/locations/asia-northeast1/functions/function-2",
			},
			"buildConfiguration": {"environmentVariables": [{"key": "TEST_VALUE_PASSWORD"}]},
			"serviceConfiguration": {"environmentVariables": []},
		},
		{
			"metadata": {
				"id": "googlecloud-cf-function|514897777777|projects/test-project-1/locations/asia-northeast1/functions/function-3",
				"displayName": "projects/test-project-1/locations/asia-northeast1/functions/function-3",
			},
			"buildConfiguration": {"environmentVariables": []},
			"serviceConfiguration": {"environmentVariables": [{"key": "TEST_RUNTIME_TOKEN"}]},
		},
	]}}]}}
}
