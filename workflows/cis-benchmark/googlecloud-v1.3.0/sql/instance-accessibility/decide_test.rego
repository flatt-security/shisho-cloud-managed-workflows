package policy.googlecloud.sql.instance_accessibility

import data.shisho
import future.keywords

test_whether_proper_accessibility_is_configured_for_cloud_sql if {
	# check if the accessibility is configured properly for Google Cloud SQL instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-mysql-1"},
			"settings": {"ipConfiguration": {"authorizedNetworks": [{
				"name": "test",
				"value": "199.27.25.0/24",
			}]}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-posgre-2"},
			"settings": {"ipConfiguration": {"authorizedNetworks": [{
				"name": "test",
				"value": "199.27.36.0/28",
			}]}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893258888|test-posgre-3"},
			"settings": {"ipConfiguration": {"authorizedNetworks": []}},
		},
	]}}]}}

	# check if the accessibility is not configured properly for Google Cloud SQL instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-mysql-1"},
			"settings": {"ipConfiguration": {"authorizedNetworks": [{
				"name": "test",
				"value": "0.0.0.0/0",
			}]}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-posgre-2"},
			"settings": {"ipConfiguration": {"authorizedNetworks": [{
				"name": "test",
				"value": "0.0.0.0/0",
			}]}},
		},
	]}}]}}
}
