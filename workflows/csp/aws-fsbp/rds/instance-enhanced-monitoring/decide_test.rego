package policy.aws.rds.instance_enhanced_monitoring

import data.shisho
import future.keywords

test_enhanced_monitoring_of_rds_databases_will_be_allowed if {
	count([d |
		decisions[d]
		shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-aurora-mysql-1-instance-1",
				"displayName": "test-aurora-mysql-1-instance-1",
			},
			"engine": "AURORA_MYSQL",
			"enhancedMonitoringResourceArn": "arn:aws:logs:ap-northeast-1:779397777777:log-group:RDSOSMetrics:log-stream:db-XZNQPEDTXYD6QVHQBNRSGPEGMU",
			"monitoringInterval": 60,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-mysql-1",
				"displayName": "test-mysql-1",
			},
			"engine": "MYSQL",
			"enhancedMonitoringResourceArn": "arn:aws:logs:ap-northeast-1:779397777777:log-group:RDSOSMetrics:log-stream:db-KUPEC2EGO5NXRGOLNVFSOVWWF4",
			"monitoringInterval": 60,
		},
	]}}]}}
}

test_enhanced_monitoring_of_rds_databases_will_be_denied if {
	count([d |
		decisions[d]
		not shisho.decision.is_allowed(d)
	]) == 2 with input as {"aws": {"accounts": [{"rds": {"instances": [
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|docdb-2023-06-28-12-28-51",
				"displayName": "docdb-2023-06-28-12-28-51",
			},
			"engine": "DOCDB",
			"enhancedMonitoringResourceArn": "",
			"monitoringInterval": 0,
		},
		{
			"metadata": {
				"id": "aws-rds-db-instance|ap-northeast-1|test-neptune-cluster-1-instance-1",
				"displayName": "test-neptune-cluster-1-instance-1",
			},
			"engine": "NEPTUNE",
			"enhancedMonitoringResourceArn": "",
			"monitoringInterval": 0,
		},
	]}}]}}
}
