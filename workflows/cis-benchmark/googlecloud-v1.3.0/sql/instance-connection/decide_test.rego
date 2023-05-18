package policy.googlecloud.sql.instance_connection

import data.shisho
import future.keywords

test_whether_proper_ssl_connection_is_required_for_cloud_sql if {
	# check if the SSL connection is required for Google Cloud SQL instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893259785|test-mysql-1"},
			"settings": {"ipConfiguration": {"requireSsl": true}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893259785|test-postgre-1"},
			"settings": {"ipConfiguration": {"requireSsl": true}},
		},
	]}}]}}

	# check if the SSL connection is not required for Google Cloud SQL instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893259785|test-mysql-1"},
			"settings": {"ipConfiguration": {"requireSsl": false}},
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893259785|test-postgre-1"},
			"settings": {"ipConfiguration": {"requireSsl": false}},
		},
	]}}]}}
}
