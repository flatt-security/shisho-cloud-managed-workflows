package policy.googlecloud.sql.instance_public_ip

import data.shisho
import future.keywords

test_whether_proper_public_ip_address_is_assigned_for_cloud_sql if {
	# check if the public IP address is assigned for Google Cloud SQL instances
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 4 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-mysql-1"},
			"instanceType": "CLOUD_SQL_INSTANCE",
			"ipAddresses": [{
				"ipAddress": "10.99.32.15",
				"ipAddressType": "PRIVATE",
			}],
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-1"},
			"instanceType": "CLOUD_SQL_INSTANCE",
			"ipAddresses": [{
				"ipAddress": "10.99.32.3",
				"ipAddressType": "PRIVATE",
			}],
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-2"},
			"instanceType": "READ_REPLICA_INSTANCE",
			"ipAddresses": [{
				"ipAddress": "35.200.66.251",
				"ipAddressType": "PRIMARY",
			}],
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-3"},
			"instanceType": "CLOUD_SQL_INSTANCE",
			"ipAddresses": [],
		},
	]}}]}}

	# check if the public IP address is not assigned for Google Cloud SQL instances
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 3 with input as {"googleCloud": {"projects": [{"cloudSql": {"instances": [
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-mysql-1"},
			"instanceType": "CLOUD_SQL_INSTANCE",
			"ipAddresses": [{
				"ipAddress": "35.200.66.253",
				"ipAddressType": "PRIMARY",
			}],
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-1"},
			"instanceType": "CLOUD_SQL_INSTANCE",
			"ipAddresses": [{
				"ipAddress": "35.200.66.254",
				"ipAddressType": "PRIMARY",
			}],
		},
		{
			"metadata": {"id": "googlecloud-sql-instance|514893257777|test-postgre-2"},
			"instanceType": "CLOUD_SQL_INSTANCE",
			"ipAddresses": [{
				"ipAddress": "35.200.66.251",
				"ipAddressType": "PRIMARY",
			}],
		},
	]}}]}}
}
