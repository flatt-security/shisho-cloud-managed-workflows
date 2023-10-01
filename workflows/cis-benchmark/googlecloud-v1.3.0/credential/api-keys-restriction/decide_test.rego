package policy.googlecloud.credential.api_keys_restriction

import data.shisho
import future.keywords

test_whether_api_keys_are_restricted_by_hosts_or_apps if {
	# check if the API keys are restricted by hosts or apps
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"credentials": {"apiKeys": [
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f7777777",
				"displayName": "test-api-key-1",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationBrowserRestriction",
				"allowedReferrers": ["example.com", "example.org"],
			}},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f8888888",
				"displayName": "test-api-key-2",
			},
			"deletedAt": "2022-01-01T00:00:00Z",
			"restriction": {"applicationRestriction": null},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f9999999",
				"displayName": "test-api-key-3",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationServerRestriction",
				"allowedIpAddresses": ["213.12.12.234"],
			}},
		},
	]}}]}}

	# check if the API keys are not restricted by hosts or apps
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 7 with input as {"googleCloud": {"projects": [{"credentials": {"apiKeys": [
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f7777777",
				"displayName": "test-api-key-1",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationBrowserRestriction",
				"allowedReferrers": ["*"],
			}},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f7777778",
				"displayName": "test-api-key-2",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationBrowserRestriction",
				"allowedReferrers": ["*.com"],
			}},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f7777779",
				"displayName": "test-api-key-3",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationBrowserRestriction",
				"allowedReferrers": ["example.*"],
			}},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f8888888",
				"displayName": "test-api-key-4",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": null},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f9999999",
				"displayName": "test-api-key-5",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationServerRestriction",
				"allowedIpAddresses": ["0.0.0.0"],
			}},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f9999990",
				"displayName": "test-api-key-6",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationServerRestriction",
				"allowedIpAddresses": ["0.0.0.0/0"],
			}},
		},
		{
			"metadata": {
				"id": "googlecloud-cre-api-key|514897777777|47bf78cc-9c32-42c6-a541-d428f9999991",
				"displayName": "test-api-key-7",
			},
			"deletedAt": null,
			"restriction": {"applicationRestriction": {
				"__typename": "GoogleCloudAPIKeyApplicationServerRestriction",
				"allowedIpAddresses": ["::0"],
			}},
		},
	]}}]}}
}
